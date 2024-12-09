# Use a minimal base image
FROM alpine:latest

# Install dependencies (stress-ng and bash)
RUN apk add --no-cache stress-ng bash

# Copy the script into the container
COPY stresser.sh /usr/local/bin/stresser.sh

# Ensure the script is executable
RUN chmod +x /usr/local/bin/stresser.sh

# Default command to run the script
CMD ["bash", "/usr/local/bin/stresser.sh", "60", "60"]
