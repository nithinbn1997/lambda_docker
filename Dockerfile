FROM python:3.9.16

WORKDIR /app

COPY requirements.txt .
RUN pip install -r requirements.txt

COPY . .

EXPOSE 8001

CMD ["uvicorn", "app.lambda_function:app", "--host", "0.0.0.0", "--port", "8001"]