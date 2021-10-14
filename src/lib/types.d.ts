export interface WebResponse {
    message: string;
    type: "error" | "warning" | "ok";
}

type Time = number;
type IP = string;
type Email = string;
type PreSessionID = `psid${string}`;
type UserID = `u${string}`;
type FirstFactorToken = `fft${string}`;
type SessionID = `sid${string}`;
type EmailToken = `emt${string}`;
type TOTPSecret = string;

// TODO
type WebAuthnChallenge = any;
interface WebAuthnKey {
    credID: string;
}

export interface Login {
    time: Time;
    ip: IP;
    email: Email;
    preSessionId: PreSessionID;
    emailToken: EmailToken;
    userId?: UserID;
    firstFactorToken: FirstFactorToken;
    webAuthnLoginChallenge: WebAuthnChallenge;
}

export interface User {
    totpActive: boolean;
    totpSecret: TOTPSecret;
    webAuthnActive: boolean;
    webAuthnKey: WebAuthnKey;
    webAuthnRegisterChallenge: WebAuthnChallenge;
    userId: UserID;
}

export interface Session {
    userId: UserID;
}
