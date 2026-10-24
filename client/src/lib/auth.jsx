import { createContext, useContext, useState } from 'react';
import { api } from './api.js';
import { generateIdentity, unlockIdentity, deriveAuthSecret } from './crypto.js';

// The unlocked private key + KEK are kept only in memory. A page refresh
// means the user has to log in again - that is intentional.
const Ctx = createContext(null);

export function AuthProvider({ children }) {
  const [session, setSession] = useState(null);

  async function finish(data, password) {
    const keys = await unlockIdentity(password, data.user);
    sessionStorage.setItem('sv_token', data.token);
    setSession({ user: data.user, ...keys });
  }

  async function register(email, password) {
    const identity = await generateIdentity(password);
    const authSecret = await deriveAuthSecret(email, password); // the password itself never leaves the browser
    const { data } = await api.post('/auth/register', { email, authSecret, ...identity });
    await finish(data, password);
  }

  async function login(email, password, otp) {
    const authSecret = await deriveAuthSecret(email, password);
    const { data } = await api.post('/auth/login', { email, authSecret, otp });
    if (data.mfaRequired) return { mfaRequired: true };
    await finish(data, password);
    return {};
  }

  const markMfaEnabled = () => setSession((s) => (s ? { ...s, user: { ...s.user, mfaEnabled: true } } : s));

  function logout() {
    sessionStorage.removeItem('sv_token');
    setSession(null);
  }

  return (
    <Ctx.Provider value={{ user: session?.user, privateKey: session?.privateKey, kek: session?.kek, register, login, logout, setSession, markMfaEnabled }}>
      {children}
    </Ctx.Provider>
  );
}

export const useAuth = () => useContext(Ctx);
