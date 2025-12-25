FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY auth_validator.py .

ENV PORT=8080
ENV AZURE_CLIENT_ID=d63e5ccd-bd26-4b10-91b7-2dd7052577cb
ENV TEST_MODE=true

EXPOSE 8080

CMD ["python", "auth_validator.py"]
