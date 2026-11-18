# Stage 1: Build
FROM mcr.microsoft.com/dotnet/sdk:6.0 AS build

WORKDIR /src

COPY . .

RUN dotnet restore eShopOnWeb.sln

RUN dotnet build eShopOnWeb.sln \
    --configuration Release \
    --no-restore

RUN dotnet publish src/Web/Web.csproj \
    --configuration Release \
    --no-restore \
    --output /app/publish

# Stage 2: Runtime
FROM mcr.microsoft.com/dotnet/aspnet:6.0

WORKDIR /app

COPY --from=build /app/publish .

ENV ASPNETCORE_URLS=http://+:8080
ENV ASPNETCORE_ENVIRONMENT=Development

EXPOSE 8080

ENTRYPOINT ["dotnet", "Web.dll"]