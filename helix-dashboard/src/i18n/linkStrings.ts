/*
 * Copyright 2026 HelixIAM contributors
 * SPDX-License-Identifier: Apache-2.0
 */

// Federated links: the admin console's "Linked identities" (confirm / revoke trust) and the account console's
// "Link" action. en + nl, merged into the dictionaries (dictionaries.ts spreads them in; the parity test covers them).

import type { Dict } from "./dictionaries";

export const linkEn: Dict = {
  "userDetail.tab.identities": "Linked identities",
  "userIdentities.title": "Linked identities",
  "userIdentities.description": "External identity providers this user signs in through, and how each link was made. Links made by matching an e-mail address never sign in an administrator.",
  "userIdentities.loading": "Loading linked identities…",
  "userIdentities.load.error": "Could not load linked identities",
  "userIdentities.empty": "This user has no linked identities.",
  "userIdentities.via.JIT": "Created at sign-in",
  "userIdentities.via.SELF": "Linked by the user",
  "userIdentities.via.WALLET": "Wallet, linked by the user",
  "userIdentities.via.ADMIN_CONFIRMED": "Confirmed by a realm admin",
  "userIdentities.via.LEGACY": "From before rc.12",
  "userIdentities.via.AUTO": "Matched by e-mail",
  "userIdentities.trusted": "Can sign in an admin",
  "userIdentities.untrusted": "Never signs in an admin",
  "userIdentities.confirm": "Confirm link",
  "userIdentities.revoke": "Revoke trust",
  "userIdentities.working": "Saving…",
  "userIdentities.realmAdminOnly": "Only a realm admin can confirm links or revoke trust in them.",
  "userIdentities.confirm.dialog.title": "Confirm this link?",
  "userIdentities.confirm.dialog.message": "The identity at \"{provider}\" will be able to sign in as this user, even when the user is an administrator. Confirm only when you know the identity is theirs.",
  "userIdentities.revoke.dialog.title": "Revoke trust in this link?",
  "userIdentities.revoke.dialog.message": "The identity at \"{provider}\" will no longer sign this user in while they are an administrator. The user can link it again from their account console.",
  "userIdentities.confirmed": "Link confirmed",
  "userIdentities.revoked": "Trust revoked",
  "userIdentities.action.error": "Could not change the link",

  "account.identities.available.title": "Link a provider",
  "account.identities.available.subtitle": "Sign in at the provider to confirm the account is yours. You may be asked for your password first.",
  "account.identities.available.empty": "This realm has no providers you can link.",
  "account.identities.link": "Link",
  "account.identities.relink": "Link again",
  "account.identities.linkNamed": "Link {provider}",
  "account.identities.link.error": "Could not start linking",
  "account.identities.error.choose": "Choose a provider to link.",
  "account.identities.error.unknown": "This realm does not offer that provider.",
};

export const linkNl: Dict = {
  "userDetail.tab.identities": "Gekoppelde identiteiten",
  "userIdentities.title": "Gekoppelde identiteiten",
  "userIdentities.description": "Externe identiteitsproviders waarmee deze gebruiker inlogt, en hoe elke koppeling is gemaakt. Koppelingen op basis van een e-mailadres loggen nooit een beheerder in.",
  "userIdentities.loading": "Gekoppelde identiteiten laden…",
  "userIdentities.load.error": "Gekoppelde identiteiten konden niet worden geladen",
  "userIdentities.empty": "Deze gebruiker heeft geen gekoppelde identiteiten.",
  "userIdentities.via.JIT": "Aangemaakt bij inloggen",
  "userIdentities.via.SELF": "Gekoppeld door de gebruiker",
  "userIdentities.via.WALLET": "Wallet, gekoppeld door de gebruiker",
  "userIdentities.via.ADMIN_CONFIRMED": "Bevestigd door een realmbeheerder",
  "userIdentities.via.LEGACY": "Van vóór rc.12",
  "userIdentities.via.AUTO": "Gekoppeld op e-mailadres",
  "userIdentities.trusted": "Kan een beheerder inloggen",
  "userIdentities.untrusted": "Logt nooit een beheerder in",
  "userIdentities.confirm": "Koppeling bevestigen",
  "userIdentities.revoke": "Vertrouwen intrekken",
  "userIdentities.working": "Opslaan…",
  "userIdentities.realmAdminOnly": "Alleen een realmbeheerder kan koppelingen bevestigen of het vertrouwen erin intrekken.",
  "userIdentities.confirm.dialog.title": "Deze koppeling bevestigen?",
  "userIdentities.confirm.dialog.message": "De identiteit bij \"{provider}\" kan dan als deze gebruiker inloggen, ook als de gebruiker beheerder is. Bevestig alleen als u weet dat de identiteit van deze gebruiker is.",
  "userIdentities.revoke.dialog.title": "Vertrouwen in deze koppeling intrekken?",
  "userIdentities.revoke.dialog.message": "De identiteit bij \"{provider}\" logt deze gebruiker niet meer in zolang die beheerder is. De gebruiker kan de provider opnieuw koppelen vanuit de accountconsole.",
  "userIdentities.confirmed": "Koppeling bevestigd",
  "userIdentities.revoked": "Vertrouwen ingetrokken",
  "userIdentities.action.error": "De koppeling kon niet worden gewijzigd",

  "account.identities.available.title": "Een provider koppelen",
  "account.identities.available.subtitle": "Log in bij de provider om te bevestigen dat het account van u is. Mogelijk wordt eerst om uw wachtwoord gevraagd.",
  "account.identities.available.empty": "Deze realm heeft geen providers die u kunt koppelen.",
  "account.identities.link": "Koppelen",
  "account.identities.relink": "Opnieuw koppelen",
  "account.identities.linkNamed": "{provider} koppelen",
  "account.identities.link.error": "Koppelen kon niet worden gestart",
  "account.identities.error.choose": "Kies een provider om te koppelen.",
  "account.identities.error.unknown": "Deze realm biedt die provider niet aan.",
};
