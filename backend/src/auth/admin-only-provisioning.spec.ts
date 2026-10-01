/**
 * Security spec: POST /api/auth/invite is gated to ADMIN role only.
 *
 * Contract (workers implement TO this file):
 *   - No cookie → 401
 *   - Role USER  → 403
 *   - Role MANAGER → 403
 *   - Role ADMIN → 201 with body.token matching /^[a-f0-9]{48}$/
 *
 * This spec FAILS before @RequireAdmin() is added to AuthController.invite()
 * because USER/MANAGER sessions currently reach the handler and get 201.
 */

import { INestApplication } from '@nestjs/common';
import { APP_GUARD } from '@nestjs/core';
import { Test } from '@nestjs/testing';
import { JwtModule, JwtService } from '@nestjs/jwt';
import { Reflector } from '@nestjs/core';
import * as cookieParser from 'cookie-parser';
import * as request from 'supertest';

import { AuthController } from './auth.controller';
import { AuthService } from './auth.service';
import { JwtAuthGuard } from './jwt-auth.guard';
import { RolesGuard } from './roles.guard';

const TEST_SECRET = 'test-secret-for-admin-only-provisioning-spec';
const TOKEN_BODY = 'a'.repeat(48);

describe('POST /api/auth/invite — admin-only provisioning', () => {
  let app: INestApplication;
  let jwtService: JwtService;

  beforeAll(async () => {
    const moduleRef = await Test.createTestingModule({
      imports: [
        JwtModule.register({
          secret: TEST_SECRET,
          signOptions: { expiresIn: '1h' },
        }),
      ],
      controllers: [AuthController],
      providers: [
        {
          provide: AuthService,
          useValue: {
            createInvite: jest.fn().mockResolvedValue({ token: TOKEN_BODY }),
          },
        },
        Reflector,
        { provide: APP_GUARD, useClass: JwtAuthGuard },
        { provide: APP_GUARD, useClass: RolesGuard },
      ],
    }).compile();

    app = moduleRef.createNestApplication();
    app.use(cookieParser());
    await app.init();

    jwtService = moduleRef.get(JwtService);
  });

  afterAll(async () => {
    await app.close();
  });

  async function sessionCookie(role: string): Promise<string> {
    const token = await jwtService.signAsync({ userId: 'u1', role, firmId: null });
    const cookieName = process.env.SESSION_COOKIE_NAME ?? 'session';
    return `${cookieName}=${token}`;
  }

  it('returns 401 with no session cookie', async () => {
    await request(app.getHttpServer())
      .post('/api/auth/invite')
      .expect(401);
  });

  it('returns 403 for a USER session', async () => {
    const cookie = await sessionCookie('USER');
    await request(app.getHttpServer())
      .post('/api/auth/invite')
      .set('Cookie', cookie)
      .expect(403);
  });

  it('returns 403 for a MANAGER session', async () => {
    const cookie = await sessionCookie('MANAGER');
    await request(app.getHttpServer())
      .post('/api/auth/invite')
      .set('Cookie', cookie)
      .expect(403);
  });

  it('returns 201 with a 48-hex token for an ADMIN session', async () => {
    const cookie = await sessionCookie('ADMIN');
    const res = await request(app.getHttpServer())
      .post('/api/auth/invite')
      .set('Cookie', cookie)
      .expect(201);

    expect(res.body).toHaveProperty('token');
    expect(res.body.token).toMatch(/^[a-f0-9]{48}$/);
  });
});
