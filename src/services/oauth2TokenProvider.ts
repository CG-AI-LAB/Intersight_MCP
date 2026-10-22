/*
 * MIT License
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

import fetch from 'node-fetch';

export interface OAuth2ClientCredentials {
  clientId: string;
  clientSecret: string;
  tokenUrl: string;
}

interface TokenResponse {
  access_token?: string;
  expires_in?: number;
}

// Refresh this long before the stated expiry so in-flight requests don't carry a token that lapses mid-call
const REFRESH_MARGIN_MS = 60_000;

/**
 * Obtains and caches Intersight access tokens using the OAuth2 client credentials grant
 */
export class OAuth2TokenProvider {
  private credentials: OAuth2ClientCredentials;
  private accessToken: string | null = null;
  private refreshAt = 0;
  private pendingRequest: Promise<string> | null = null;

  constructor(credentials: OAuth2ClientCredentials) {
    this.credentials = credentials;
  }

  async getToken(): Promise<string> {
    if (this.accessToken && Date.now() < this.refreshAt) {
      return this.accessToken;
    }

    // Concurrent callers share one token request instead of each fetching their own
    if (!this.pendingRequest) {
      this.pendingRequest = this.requestToken().finally(() => {
        this.pendingRequest = null;
      });
    }
    return this.pendingRequest;
  }

  /**
   * Discard the cached token, e.g. after the API rejects it
   */
  invalidate(): void {
    this.accessToken = null;
    this.refreshAt = 0;
  }

  private async requestToken(): Promise<string> {
    const response = await fetch(this.credentials.tokenUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Accept': 'application/json'
      },
      body: new URLSearchParams({
        grant_type: 'client_credentials',
        client_id: this.credentials.clientId,
        client_secret: this.credentials.clientSecret
      }).toString()
    });

    if (!response.ok) {
      const errorText = await response.text();
      throw new Error(`Intersight OAuth2 token request failed: ${response.status} - ${errorText}`);
    }

    const token = await response.json() as TokenResponse;
    if (!token.access_token) {
      throw new Error('Intersight OAuth2 token response did not include an access_token');
    }

    const lifetimeMs = (token.expires_in ?? 0) * 1000;
    this.accessToken = token.access_token;
    this.refreshAt = Date.now() + lifetimeMs - Math.min(REFRESH_MARGIN_MS, lifetimeMs / 2);
    return this.accessToken;
  }
}
