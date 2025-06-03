FROM node:20-alpine AS build-app
ARG configuration=production

WORKDIR /dist/src/app

RUN npm cache clean --force

COPY . .
RUN npm install

RUN npm run ng build -- --configuration=$configuration

FROM nginx:latest AS ngi

COPY --from=build-app /dist/src/app/dist/audit_visualization/browser /usr/share/nginx/html
COPY nginx.conf  /etc/nginx/conf.d/default.conf

EXPOSE 80