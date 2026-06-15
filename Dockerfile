FROM python:3.11-slim-bookworm

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    cmake \
    git \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

RUN pip install --no-cache-dir cryptography matplotlib numpy

RUN git clone --depth=1 https://github.com/open-quantum-safe/liboqs.git \
    && cmake -S liboqs -B liboqs/build -DBUILD_SHARED_LIBS=ON \
    && cmake --build liboqs/build --target install

RUN git clone --depth=1 https://github.com/open-quantum-safe/liboqs-python.git \
    && cd liboqs-python && pip install --no-cache-dir .

ENV LD_LIBRARY_PATH=/usr/local/lib

COPY . /app

ENTRYPOINT ["python3"]
CMD ["-m", "src.utils.benchmark"]
