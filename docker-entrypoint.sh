#!/bin/bash
set -e

# InfraGuard Docker Entrypoint Script
# Handles initialization, AWS credential validation, and command execution

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}🔒 InfraGuard Security Scanner${NC}"
echo "================================"

# Function to check if AWS credentials are configured
check_aws_credentials() {
    echo -e "${YELLOW}→ Checking AWS credentials...${NC}"
    
    if [ -n "$AWS_ACCESS_KEY_ID" ] && [ -n "$AWS_SECRET_ACCESS_KEY" ]; then
        echo -e "${GREEN}✓ AWS credentials found (environment variables)${NC}"
        return 0
    elif [ -f "$HOME/.aws/credentials" ]; then
        echo -e "${GREEN}✓ AWS credentials found (credentials file)${NC}"
        return 0
    else
        echo -e "${RED}✗ No AWS credentials found${NC}"
        echo "Please provide AWS credentials via:"
        echo "  1. Environment variables: AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY"
        echo "  2. Mount ~/.aws directory"
        echo ""
        echo "Example:"
        echo "  docker run -e AWS_ACCESS_KEY_ID=xxx -e AWS_SECRET_ACCESS_KEY=xxx infraguard:latest check-all"
        exit 1
    fi
}

# Function to validate AWS region
validate_aws_region() {
    if [ -z "$AWS_REGION" ]; then
        export AWS_REGION=eu-north-1
        echo -e "${YELLOW}! AWS_REGION not set, using default: eu-north-1${NC}"
    else
        echo -e "${GREEN}✓ AWS region: $AWS_REGION${NC}"
    fi
}

# Function to create output directory
setup_output_directory() {
    if [ ! -d "/app/scan-results" ]; then
        mkdir -p /app/scan-results
        echo -e "${GREEN}✓ Created scan-results directory${NC}"
    fi
}

# Main execution
main() {
    # Skip credential check for help commands
    if [[ "$1" == "--help" ]] || [[ "$1" == "-h" ]] || [ $# -eq 0 ]; then
        exec python main.py "$@"
        exit 0
    fi
    
    # Validate environment
    check_aws_credentials
    validate_aws_region
    setup_output_directory
    
    echo -e "${GREEN}✓ Environment ready${NC}"
    echo "================================"
    echo ""
    
    # Execute the command
    exec python main.py "$@"
}

# Run main function
main "$@"
