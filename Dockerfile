FROM python:3.12-slim
ENV PYTHONUNBUFFERED=1 PORT=8000
WORKDIR /app
RUN useradd -m app
COPY main.py dashboard.html ./
COPY assets/logo.png assets/logo.png
COPY langflow/ langflow/
USER app
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=3s CMD python -c "import urllib.request;urllib.request.urlopen('http://localhost:8000/')" || exit 1
CMD ["python", "main.py"]
