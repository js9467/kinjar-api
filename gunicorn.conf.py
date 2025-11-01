import os

# Server socket
bind = "0.0.0.0:8080"

# Worker processes
workers = 1
worker_class = "sync"
timeout = 300  # Increased to 5 minutes for file uploads
worker_connections = 1000
max_requests = 1000
max_requests_jitter = 50

# Logging
accesslog = "-"
errorlog = "-"
loglevel = "info"

# Server mechanics
daemon = False
preload_app = False

# For large file uploads
worker_tmp_dir = "/dev/shm"