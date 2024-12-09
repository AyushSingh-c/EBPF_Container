# Use an official lightweight Linux base image
FROM ubuntu:latest

# Install necessary dependencies
RUN apt-get update && apt-get install -y \
    clang llvm libbpf-dev m4 gcc gcc-multilib g++ make iproute2 iputils-ping curl build-essential libncurses-dev bison flex libssl-dev libelf-dev python3 python3-full\
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# Set working directory in the container
WORKDIR /app

# Copy the project files into the container
COPY ./webapp /app/webapp
COPY ./src /app/src
COPY ./Makefile /app/Makefile

# Build the eBPF programs
RUN make -C /app

# Create a virtual environment
RUN python3 -m venv /env

# Set environment variables to use the virtual environment
ENV PATH="/env/bin:$PATH"

# Install Flask inside the virtual environment
RUN pip install flask

# Expose the port the app runs on
EXPOSE 5000

# Running the webapp with current context 
CMD ["python3", "/app/webapp/app.py"]
