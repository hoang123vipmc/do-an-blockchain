# Sử dụng image Python phiên bản siêu nhẹ
FROM python:3.13-slim

# Thiết lập thư mục làm việc trong container
WORKDIR /app

# Thiết lập các biến môi trường cho Python
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Copy file requirements.txt vào trước để tận dụng Docker Cache
COPY requirements.txt .

# Cài đặt các thư viện cần thiết
RUN pip install --no-cache-dir -r requirements.txt

# Copy toàn bộ mã nguồn vào thư mục làm việc (trừ các file trong .dockerignore)
COPY . .

# Expose port (Mặc định 5000 nhưng có thể cấu hình qua biến môi trường PORT)
EXPOSE 5000

# Lệnh khởi chạy ứng dụng bằng Gunicorn (Chuẩn Production)
CMD ["sh", "-c", "gunicorn -w 2 -b 0.0.0.0:${PORT:-5000} run:app"]
