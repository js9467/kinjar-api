import os

# Server socket
bind = "0.0.0.0:8080"

# Worker processes
workers = 1
worker_class = "sync"
timeout = 120

# Logging
accesslog = "-"
errorlog = "-"
loglevel = "info"

# Server mechanics
daemon = False
preload_app = False