# (1) Билдим приложение
FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build
WORKDIR /app

# Копируем всё из текущей папки (где Dockerfile)
COPY . .

# Публикуем проект в Release-режиме
RUN dotnet publish -c Release -o out

# (2) Рантайм-контейнер
FROM mcr.microsoft.com/dotnet/aspnet:8.0 AS final
WORKDIR /app

COPY --from=build /app/out .

# Приложение слушает на порту 80
ENV ASPNETCORE_URLS=http://+:80

ENTRYPOINT ["dotnet", "api.dll"]
