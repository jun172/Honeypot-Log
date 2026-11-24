FROM python:3.12-slim

WORKDIR /app

COPY dashboard/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY dashboard/ .

# startup.sh に実行権限を付与
RUN chmod +x /app/startup.sh

CMD ["/app/startup.sh"]