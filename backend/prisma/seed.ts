import { PrismaClient } from '@prisma/client'
import argon2 from 'argon2'

const prisma = new PrismaClient()

async function main() {
  const ARGON_OPTS = { type: argon2.argon2id, memoryCost: 65536, timeCost: 3, parallelism: 4 } as const

  const owner = await prisma.user.upsert({
    where: { username: 'admin' },
    update: {},
    create: {
      username: 'admin',
      email: 'admin@immortal.local',
      passwordHash: await argon2.hash('Imm0rtal!Owner#2024$Secure', ARGON_OPTS),
      role: 'OWNER',
      status: 'ACTIVE',
    },
  })
  console.log('Owner created:', owner.username)

  const product = await prisma.product.upsert({
    where: { slug: 'immortal-private' },
    update: {},
    create: { name: 'Immortal Private', slug: 'immortal-private', description: 'Immortal Software licensed product' },
  })
  console.log('Product created:', product.name)

  await prisma.plan.upsert({
    where: { id: 'plan-cs2-monthly' },
    update: {},
    create: {
      id: 'plan-cs2-monthly',
      productId: product.id,
      name: 'Monthly',
      durationDays: 30,
      price: 15.00,
    },
  })

  await prisma.plan.upsert({
    where: { id: 'plan-cs2-lifetime' },
    update: {},
    create: {
      id: 'plan-cs2-lifetime',
      productId: product.id,
      name: 'Lifetime',
      durationDays: 36500,
      price: 80.00,
    },
  })

  console.log('Plans created')
}

main()
  .catch(e => { console.error(e); process.exit(1) })
  .finally(() => prisma.$disconnect())
