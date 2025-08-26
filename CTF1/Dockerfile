FROM python:3.11-slim
WORKDIR /app
COPY . /app
RUN pip install --no-cache-dir -r requirements.txt
# create a flag file in image
RUN echo "RedX{SSTI_READS_THE_FLAG}" > /flag && chmod 400 /flag
EXPOSE 5000
CMD ["python", "app.py"]
