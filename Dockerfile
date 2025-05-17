# Dockerfile
# -------- Build Stage --------
FROM node:22 AS builder

WORKDIR /app

# Install pnpm globally (choose a specific stable version if you like)
RUN npm install -g pnpm

# Install dependencies
COPY package.json pnpm-lock.yaml* ./
RUN pnpm install --frozen-lockfile

# Copy source
COPY . .

# If you have a build step (e.g. TypeScript), run it here:
# RUN pnpm run build

# -------- Production Stage --------
FROM node:22

# Create a non-root user
RUN groupadd --system appgroup \
 && useradd  --system --gid appgroup --home-dir /app --shell /usr/sbin/nologin appuser

WORKDIR /app

# Copy built app & deps, preserve ownership
COPY --from=builder --chown=appuser:appgroup /app ./

USER appuser
ENV NODE_ENV=production
EXPOSE 3000

# Adjust this to your actual startup file
CMD ["node", "server.js"]
