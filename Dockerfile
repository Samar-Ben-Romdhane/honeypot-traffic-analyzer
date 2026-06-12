# --- Stage 1: Frontend and Backend Bundler Build ---
FROM node:20-alpine AS builder
WORKDIR /app

# Copy system scripts
COPY package*.json tsconfig.json vite.config.ts server.ts ./
COPY src ./src
COPY index.html ./index.html

# Install and compile distribution assets
RUN npm ci
RUN npm run build

# --- Stage 2: Production Execution Image ---
FROM node:20-alpine AS runner
WORKDIR /app
ENV NODE_ENV=production
ENV PORT=3000

# Copy built artifacts and runtime instructions
COPY --from=builder /app/package*.json ./
COPY --from=builder /app/dist ./dist

# Install production dependencies only to minimize image footprint
RUN npm ci --only=production

EXPOSE 3000
EXPOSE 2222
EXPOSE 2323
EXPOSE 8080

CMD ["npm", "start"]