# Build stage
FROM ubuntu:24.04 AS builder

# Use bash and enable pipefail
SHELL ["/bin/bash", "-o", "pipefail", "-c"]

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    xz-utils \
    git \
    build-essential \
    pkg-config \
    libssl-dev \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Install Zig 0.14.1 based on architecture
ARG TARGETARCH
RUN ZIG_VERSION="0.14.1" && \
    case "$TARGETARCH" in \
        amd64) ZIG_ARCH="x86_64" ;; \
        arm64) ZIG_ARCH="aarch64" ;; \
        arm) ZIG_ARCH="armv7a" ;; \
        386) ZIG_ARCH="x86" ;; \
        riscv64) ZIG_ARCH="riscv64" ;; \
        *) echo "Unsupported architecture: $TARGETARCH" && exit 1 ;; \
    esac && \
    curl -L "https://ziglang.org/download/${ZIG_VERSION}/zig-${ZIG_ARCH}-linux-${ZIG_VERSION}.tar.xz" | tar -xJ && \
    mv "zig-${ZIG_ARCH}-linux-${ZIG_VERSION}" /opt/zig && \
    ln -s /opt/zig/zig /usr/local/bin/zig

# Install Rust 1.85+
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain 1.85.0
ENV PATH="/root/.cargo/bin:${PATH}"

# Install RISC0 toolchain using rzup (only for linux/amd64)
ARG TARGETARCH
RUN if [ "$TARGETARCH" = "amd64" ]; then \
        curl -L https://risczero.com/install | bash && \
        export PATH="/root/.risc0/bin:${PATH}" && \
        rzup install; \
    fi
ENV PATH="/root/.risc0/bin:${PATH}"

# Set working directory
WORKDIR /app

# Copy dependency files first for better caching
COPY build.zig.zon ./
COPY build.zig ./

# Copy source code
COPY pkgs/ ./pkgs/
COPY build/ ./build/
COPY resources/ ./resources/
COPY rust/ ./rust/
COPY LICENSE ./
COPY README.md ./

# Copy git directory to get commit hash (exclude large objects)
COPY .git/HEAD .git/HEAD
COPY .git/refs .git/refs

# Get git commit hash
RUN GIT_VERSION=$(cat .git/HEAD | grep -o '[0-9a-f]\{40\}' || echo "unknown") && \
    if [ -z "$GIT_VERSION" ] || [ "$GIT_VERSION" = "unknown" ]; then \
        REF=$(cat .git/HEAD | sed 's/ref: //'); \
        GIT_VERSION=$(cat ".git/$REF" 2>/dev/null | head -c 7 || echo "unknown"); \
    else \
        GIT_VERSION=$(echo "$GIT_VERSION" | head -c 7); \
    fi && \
    echo "Git version: $GIT_VERSION" && \
    echo "Fetching dependencies..." && \
    COUNT=0 && \
    MAX_RETRIES=3 && \
    FETCH_SUCCESS=false && \
    while [ $COUNT -lt $MAX_RETRIES ]; do \
        echo "Fetch attempt $(( $COUNT + 1 )) of $MAX_RETRIES..." && \
        if OUTPUT=$(zig build --fetch 2>&1); then \
            echo "Dependencies fetched successfully!" && \
            FETCH_SUCCESS=true && \
            break; \
        else \
            EXIT_CODE=$? && \
            echo "Fetch failed with exit code $EXIT_CODE" && \
            if echo "$OUTPUT" | grep -q "EndOfStream"; then \
                echo "EndOfStream error detected, will retry..." && \
                COUNT=$(( $COUNT + 1 )) && \
                if [ $COUNT -lt $MAX_RETRIES ]; then \
                    echo "Waiting 10 seconds before retry..." && \
                    sleep 10; \
                fi; \
            else \
                echo "Non-retryable fetch error:" && \
                echo "$OUTPUT" && \
                exit $EXIT_CODE; \
            fi; \
        fi; \
    done && \
    if [ "$FETCH_SUCCESS" = false ]; then \
        echo "Dependency fetch failed after $MAX_RETRIES attempts" && \
        exit 1; \
    fi && \
    echo "Building project with optimizations..." && \
    zig build -Doptimize=ReleaseFast -Dgit_version="$GIT_VERSION"

# Intermediate stage to prepare runtime libraries
FROM ubuntu:24.04 AS runtime-prep
ARG TARGETARCH

# Copy built binaries and resources from builder
COPY --from=builder /app/zig-out/ /app/zig-out/
COPY --from=builder /app/resources/ /app/resources/
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

# Create a script to copy the right libraries based on architecture
RUN mkdir -p /runtime-libs && \
    case "$TARGETARCH" in \
        amd64) \
            LIBDIR="x86_64-linux-gnu" && \
            LDSO="/lib64/ld-linux-x86-64.so.2" \
            ;; \
        arm64) \
            LIBDIR="aarch64-linux-gnu" && \
            LDSO="/lib/ld-linux-aarch64.so.1" \
            ;; \
        arm) \
            LIBDIR="arm-linux-gnueabihf" && \
            LDSO="/lib/ld-linux-armhf.so.3" \
            ;; \
        386) \
            LIBDIR="i386-linux-gnu" && \
            LDSO="/lib/ld-linux.so.2" \
            ;; \
        riscv64) \
            LIBDIR="riscv64-linux-gnu" && \
            LDSO="/lib/ld-linux-riscv64-lp64d.so.1" \
            ;; \
        *) \
            echo "Unsupported architecture: $TARGETARCH" && exit 1 \
            ;; \
    esac && \
    if [ -d "/lib/$LIBDIR" ]; then \
        mkdir -p "/runtime-libs/lib/$LIBDIR" && \
        for lib in libc.so.6 libm.so.6 libpthread.so.0 libdl.so.2 librt.so.1 libgcc_s.so.1 libstdc++.so.6; do \
            [ -f "/lib/$LIBDIR/$lib" ] && cp -L "/lib/$LIBDIR/$lib" "/runtime-libs/lib/$LIBDIR/" || true; \
        done; \
    fi && \
    if [ -f "$LDSO" ]; then \
        mkdir -p "/runtime-libs$(dirname $LDSO)" && \
        cp -L "$LDSO" "/runtime-libs$LDSO"; \
    fi

# Runtime stage - using scratch for absolute minimal size
FROM scratch AS runtime

# Copy the architecture-specific libraries and loader
COPY --from=runtime-prep /runtime-libs/ /

# Copy SSL certificates for HTTPS
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

# Copy built binaries
COPY --from=builder /app/zig-out/ /app/zig-out/

# Copy runtime resources
COPY --from=builder /app/resources/ /app/resources/

# Set the zeam binary as the entrypoint with beam parameter by default
ENTRYPOINT ["/app/zig-out/bin/zeam"]

# IMPORTANT NOTES:
#
#
# 1. The 'clock' and 'beam' commands use xev event loop which may have 
#    container compatibility issues. The PermissionDenied error occurs even
#    with additional capabilities. This appears to be a limitation of running
#    the xev-based event loop in a containerized environment.
#
#    Hint: Use '--security-opt seccomp=unconfined' extra docker run arg to
#    circumvent the issue.
#
# 2. The scratch image has no users, shells, or package managers - only
#    the binary and required libraries.
#
# 3. For debugging, you'll need to copy the binary to another container
#    with debugging tools.
#
# 4. The final image uses scratch base with manually copied libraries
#    for the absolute minimal size possible.
