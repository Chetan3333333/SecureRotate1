import os
bind = "0.0.0.0:" + os.environ.get("PORT", "10000")
workers = 4
threads = 10
worker_class = "gthread"
timeout = 120
