# Sử dụng image Java từ Docker Hub
FROM openjdk:17-jdk-slim

# Cài đặt thư mục làm việc trong container
WORKDIR /app

# Sao chép file JAR từ thư mục target vào container
COPY target/*.jar app.jar

# Mở port 8080 để ứng dụng có thể truy cập
EXPOSE 8080

# Lệnh để chạy ứng dụng Java
CMD ["java", "-jar", "app.jar"]

