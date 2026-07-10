import Alpine from "alpinejs";
import PocketBase, { type AuthRecord, type AuthMethodsList } from "pocketbase";
import MultiAuthStore from "./lib/multi-auth-store";
import toastStore from "./lib/toast-store";
import { postRedirect, sentenize, base64UrlDecode } from "./lib/utils";
import "./login.style.min.css";

//

// Returns true when the JWT's `exp` claim is still in the future. Used to
// avoid adopting an already-expired main-site session (which the server would
// reject, bouncing us back here in a loop).
const jwtNotExpired = (token: string): boolean => {
    try {
        const payload = JSON.parse(base64UrlDecode(token.split(".")[1] || ""));
        return typeof payload?.exp === "number" && payload.exp > Math.floor(Date.now() / 1000);
    } catch {
        return false;
    }
};

//

type LoginState = {
    page: "account-selection" | "login-password" | "login-otp" | "consent";
    state: {
        passwordLoginForm: {
            submitting: boolean;
            identity: string;
            password: string;
        };
        otpLoginForm: {
            requesting: boolean;
            submitting: boolean;
            id: string;
            prevId: string;
            identity: string;
            password: string;
        };
        consentForm: {
            submitting: boolean;
        };
        mfaId: string;
        methods: AuthMethodsList | null;
        authRecord: AuthRecord | null;
        validAccountsForReq: AuthRecord[];
    };

    params: {
        collection: string;
        client_id: string;
        client_name: string;
        redirect_uri: string;
        prompt: "login" | "none" | "consent";
        max_age?: number;
        requested_scopes: string[];
    };

    error: string;

    //

    init: () => Promise<void>;
    isEmailIdentity(): boolean;
    showAccountSelection(): boolean;
    showLoginPassword(): boolean;
    showLoginRequestOtp(): boolean;
    showLoginOtp(): boolean;
    showConsent(): boolean;
    uiUserLabel(record: AuthRecord): string;
    uiUserLabelShort(record: AuthRecord): string;
    uiIdentityLabel(): string;
    uiClientNameLabel(): string;
    uiConsentButtonLabel(): string;
    selectAccount: (record: AuthRecord) => Promise<void>;
    switchAccount: () => void;
    newAccount: () => void;
    submitAuthWithPassword: () => Promise<void>;
    submitAuthWithOTP: () => Promise<void>;
    requestOTP: () => Promise<void>;
    submitConsent: () => Promise<void>;
    handleSuccessfulLogin: () => void;
    handleSuccessfulConsent: () => void;
    handleErr: (err: any) => void;
};

Alpine.data<Partial<LoginState>, any>('oauth', () => {

    const pbAuthStore = new MultiAuthStore('__pb_oauth2_cache__');
    const pb = new PocketBase(window.location.origin, pbAuthStore);

    //

    const getValidAccountsForReq = (): AuthRecord[] => {
        return pbAuthStore.records
            .filter(item =>
                (
                    item.record?.collectionId === ret.params.collection ||
                    item.record?.collectionName === ret.params.collection
                ) &&
                (
                    item.iat + (ret.params.max_age ?? 0) > Math.floor(Date.now() / 1000)
                )
            )
            .map(item => item.record);
    };

    //

    const ret: LoginState = {
        page: "account-selection",
        state: {
            passwordLoginForm: {
                submitting: false,
                identity: "",
                password: ""
            },
            otpLoginForm: {
                requesting: false,
                submitting: false,
                id: "",
                prevId: "",
                identity: "",
                password: "",
            },
            consentForm: {
                submitting: false,
            },
            mfaId: "",
            methods: null,
            authRecord: null,
            validAccountsForReq: [],
        },

        params: {
            collection: "",
            client_id: "",
            client_name: "",
            redirect_uri: "",
            prompt: "login",
            max_age: 7 * 24 * 60 * 60, // 7 days in seconds
            requested_scopes: [],
        },

        error: "",

        //

        async init() {

            // Seamless SSO: this login page runs on the same origin as the main
            // cyoa.cafe app, and the main app's session (localStorage key
            // "pocketbase_auth") is the single source of truth for who the user
            // is. Mirror it into our own store on EVERY visit — accounts left
            // over from older visits otherwise accumulate in __pb_oauth2_cache__
            // and surface an account-picker click instead of a silent hand-off.
            // The one-shot guard prevents a redirect loop if the server ends up
            // rejecting the adopted token.
            const SSO_GUARD = "__oauth2_sso_adopted__";
            let adoptedMainSession = false;
            if (sessionStorage.getItem(SSO_GUARD)) {
                // Came back here right after adopting → the token didn't stick.
                // Drop it and fall through to the normal login form.
                sessionStorage.removeItem(SSO_GUARD);
                try { pbAuthStore.clear(); } catch { /* noop */ }
            } else {
                try {
                    const raw = window.localStorage.getItem("pocketbase_auth");
                    const parsed = raw ? JSON.parse(raw) : null;
                    const token: string | undefined = parsed?.token;
                    const record = parsed?.record ?? parsed?.model;
                    if (token && record && jwtNotExpired(token)) {
                        try { pbAuthStore.clear(); } catch { /* noop */ }
                        // save() appends and selects the record, so
                        // pbAuthStore.selected is guaranteed after this.
                        pbAuthStore.save(token, record);
                        sessionStorage.setItem(SSO_GUARD, "1");
                        adoptedMainSession = true;
                    }
                } catch { /* ignore a malformed main-site store */ }
            }

            this.state!.validAccountsForReq = getValidAccountsForReq();

            // Freshly mirrored main-site session → finish the hop silently.
            // No consent click: the forum is meant to feel like another page
            // of the same site. If the server rejects the token we bounce back
            // here once, the guard trips, and the normal form takes over.
            if (adoptedMainSession && this.params.prompt !== "login" && pbAuthStore.selected) {
                this.state!.authRecord = pbAuthStore.selected.record ?? null;
                const { token, iat } = pbAuthStore.selected;
                postRedirect(this.params.redirect_uri, { pb_token: token, pb_token_iat: iat });
                return;
            }

            if (this.params.prompt === "none") {
                if (this.state.validAccountsForReq.length === 1) {
                    // TODO/conformance: Check login_hint if provided. Return "login_required" if it doesn't match.
                    const { token, iat } = pbAuthStore.selectByRecord(this.state.validAccountsForReq[0])!;
                    postRedirect(this.params.redirect_uri, { pb_token: token, pb_token_iat: iat });
                } else if (this.state.validAccountsForReq.length > 1) {
                    // TODO/conformance: Check login_hint if provided. 
                    //       - If it matches exactly one account, return that.
                    //       - If it doesn't match any, return "login_required".
                    postRedirect(this.params.redirect_uri, { error: "account_selection_required" });
                } else {
                    postRedirect(this.params.redirect_uri, { error: "login_required" });
                }
                return;

            } else if (this.params.prompt === "consent") {
                if (this.state.validAccountsForReq.length === 1) {
                    // 🔥 Важно: сначала выбираем запись в хранилище!
                    const found = pbAuthStore.selectByRecord(this.state.validAccountsForReq[0]);
                    if (found) {
                        pbAuthStore.select(pbAuthStore.findIndex(this.state.validAccountsForReq[0]));
                    }
                    this.state!.authRecord = found?.record || null;
                    this.handleSuccessfulConsent();
                } else {
                    this.page = "account-selection";
                }
            } else if (this.params.prompt === "login") {
                this.page = "login-password";
            }

            //

            try {
                this.state!.methods = await pb.collection(this.params!.collection).listAuthMethods();

                if (this.state.validAccountsForReq.length === 0 || this.params.prompt === "login") {
                    if (this.state!.methods.password.enabled) {
                        this.page = "login-password";
                    } else if (this.state!.methods.otp.enabled) {
                        this.page = "login-otp";
                    } else {
                        throw new Error("No supported authentication methods available");
                    }
                }
            } catch (err) {
                this.handleErr(err);
            }
        },

        //

        isEmailIdentity() {
            return (
                !!this.state!.methods?.password.enabled &&
                this.state!.methods.password.identityFields.length === 1 &&
                this.state!.methods.password.identityFields[0] === "email"
            );
        },

        //

        showAccountSelection() {
            return !this.error && !!this.state!.methods && this.page === "account-selection";
        },
        showLoginPassword() {
            return !this.error && !!this.state!.methods && this.page === "login-password";
        },
        showLoginRequestOtp() {
            return !this.error && !!this.state!.methods && this.page === "login-otp" && !this.state!.otpLoginForm.id;
        },
        showLoginOtp() {
            return !this.error && !!this.state!.methods && this.page === "login-otp" && !!this.state!.otpLoginForm.id;
        },
        showConsent() {
            return !this.error && !!this.state!.methods && this.page === "consent";
        },

        //

        uiUserLabel(record: AuthRecord) {
            if (!record) {
                return "Unknown Account";
            }
            if (record.name) {
                if (record.email) {
                    return `${record.name} (${record.email})`;
                } else {
                    return `${record.name} (${record.id})`;
                }
            } else if (record.email) {
                return record.email;
            } else {
                return record.id;
            }
        },
        uiUserLabelShort(record: AuthRecord) {
            if (!record) {
                return "Unknown Account";
            }
            return record.name || record.email || record.id;
        },
        uiIdentityLabel() {
            return sentenize(`${this.state!.methods?.password?.identityFields?.join(' or ') || 'Identity'}`, false);
        },
        uiClientNameLabel() {
            return this.params.client_name || `Unnamed OAuth2 Client (${this.params.client_id?.substr(0, 8)}...)`
        },
        uiConsentButtonLabel() {
            return "Authorize " + (this.params.client_name || `Third-Party App`);
        },

        //

        async selectAccount(record: AuthRecord) {
            pbAuthStore.select(pbAuthStore.findIndex(record));
            this.handleSuccessfulLogin();
        },

        async switchAccount() {
            pbAuthStore.select(-1);
            this.state!.authRecord = null;
            this.page = "account-selection";
        },

        async newAccount() {
            this.page = "login-password";
            // TODO: clear form state
        },

        async submitAuthWithPassword() {
            if (this.state!.passwordLoginForm.submitting) {
                return;
            }

            this.state!.passwordLoginForm.submitting = true;

            const identity = this.state!.passwordLoginForm.identity;
            const password = this.state!.passwordLoginForm.password;

            try {
                await pb
                    .collection(this.params!.collection)
                    .authWithPassword(identity, password)
                    .then(() => this.handleSuccessfulLogin());
            } catch (err: any) {
                if (err.status === 401) {
                    this.state!.mfaId = err.response.mfaId;

                    if (
                        this.state!.methods?.otp.enabled &&
                        this.isEmailIdentity() ||
                        (
                            // if the identity looks like an email, we can assume it's an email
                            /^[^\@\s]+@[^\@\s]+$/.test(identity)
                        )
                    ) {
                        this.page = "login-otp";
                        this.state!.otpLoginForm.identity = identity;
                        await this.requestOTP();
                    }
                } else if (err.status !== 400) {
                    this.handleErr(err);
                } else {
                    Alpine.store("toast").addToast("error", "Invalid identity or password");
                }
            }

            this.state!.passwordLoginForm.submitting = false;
        },

        async submitAuthWithOTP() {
            if (this.state!.otpLoginForm.submitting) {
                return;
            }

            this.state!.otpLoginForm.submitting = true;

            try {
                await pb
                    .collection(this.params!.collection)
                    .authWithOTP(this.state!.otpLoginForm.id || this.state!.otpLoginForm.prevId, this.state!.otpLoginForm.password, { mfaId: this.state!.mfaId })
                    .then(() => this.handleSuccessfulLogin());
            } catch (err) {
                this.handleErr(err);
            }

            this.state!.otpLoginForm.submitting = false;
        },

        async requestOTP() {
            if (this.state!.otpLoginForm.requesting) {
                return;
            }

            this.state!.otpLoginForm.requesting = true;

            try {
                const result = await pb
                    .collection(this.params!.collection)
                    .requestOTP(this.state!.otpLoginForm.identity);
                this.state!.otpLoginForm.id = result.otpId;
                this.state!.otpLoginForm.prevId = result.otpId;
            } catch (err: any) {
                if (err.status === 429) {
                    this.state!.otpLoginForm.id = this.state!.otpLoginForm.prevId;
                }
                this.handleErr(err);
            }

            this.state!.otpLoginForm.requesting = false;
        },

        async submitConsent() {
            this.state!.consentForm.submitting = true;
            this.handleSuccessfulConsent();
        },

        //

        handleSuccessfulLogin() {
            this.state!.authRecord = pbAuthStore.selected?.record || null;
            this.state!.validAccountsForReq = getValidAccountsForReq();
            this.handleSuccessfulConsent();   
        },

        //

        handleSuccessfulConsent() {
            console.log("🚀 handleSuccessfulConsent called", {
                selected: pbAuthStore.selected,
                redirect_uri: this.params.redirect_uri
            });
            
            if (!pbAuthStore.selected) {
                console.error("❌ pbAuthStore.selected is undefined!");
                return;
            }
            
            const { token, iat } = pbAuthStore.selected;
            postRedirect(this.params.redirect_uri, { pb_token: token, pb_token_iat: iat });
        },

        //

        handleErr(err: any) {
            // @ts-ignore
            if (!err || !(err instanceof Error) || err.isAbort) {
                return;
            }
             // @ts-ignore
            const responseData = err?.data || {};
            const msg = responseData.message || err.message || "An error occurred";
            Alpine.store("toast").addToast("error", msg);
        }
    };

    //

    try {
        const stateURLParam = new URLSearchParams(window.location.search).get("state") || "";
        const stateJSON = base64UrlDecode(stateURLParam);
        const stateData = JSON.parse(stateJSON);
        if (typeof stateData !== "object" || stateData === null) {
            throw new Error("Unexpected format");
        }

        const {
            collection,
            client_id,
            redirect_uri,
            login_hint,
        } = stateData;

        if (!collection) {
            throw new Error("Missing collection");
        }
        if (!client_id) {
            throw new Error("Missing client_id");
        }
        if (!redirect_uri) {
            throw new Error("Missing redirect_uri");
        }
        if (login_hint) {
            ret.state!.passwordLoginForm.identity = String(login_hint);
        }

        ret.params!.collection = String(collection);
        ret.params!.client_id = String(client_id);
        ret.params!.client_name = String(stateData.client_name);
        ret.params!.redirect_uri = String(redirect_uri);
        ret.params!.prompt = String(stateData.prompt || "consent") as any;
        ret.params!.max_age = Number(stateData.max_age) || 7 * 24 * 60 * 60;
        ret.params!.requested_scopes = Array.from(stateData.requested_scopes || []).map(String);
    } catch (e) {
        return { error: "Invalid state: " + (e instanceof Error ? e.message : String(e)) }
    }

    return ret;
});

//

window.Alpine = Alpine;
window.Alpine.store("toast", toastStore);
window.Alpine.start();
