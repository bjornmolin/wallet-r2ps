<!--
SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government

SPDX-License-Identifier: EUPL-1.2
-->

# Skydd mot replay-attacker

Status: **BESLUTAD**

## Kontext / Problem

Utan skydd mot replay-attacker kan en angripare som avlyssnar en giltig signerad förfrågan skicka om den, och servern kan inte skilja den från en legitim förfrågan.

Ett naturligt första angreppssätt är att kräva ett unikt nonce som HTTP-frågeparameter, lagrat i Valkey av BFF:en. Det är otillräckligt: en frågeparameter befinner sig utanför den JWS-signerade `OuterRequest`. En angripare som avlyssnar en fullständig förfrågan kan ta bort nonce och ersätta det med ett nytt – jws-signaturen förblir giltig och servern saknar möjlighet att upptäcka bytet.

## Beslut

`nonce`-fältet bäddas in direkt i `OuterRequest`, som JWS-signeras av enhetens privata nyckel. BFF:en extraherar nonce via base64url-avkodning av JWS-payloadsegmentet utan att verifiera signaturen, och kontrollerar nonce mot Valkey innan förfrågan vidarebefordras till Kafka.

Nonce lagras i Valkey med nyckeln `nonce:{client_id}:{nonce}`, där `client_id` hämtas ur request-bodyn (utanför JWS). Sammansättningen innebär att olika klienter kan använda samma nonce-värde utan kollision, utan att det ger angripare något utrymme att manipulera tillhörigheten – en förändrad nonce bryter jws-signaturen oavsett vad `client_id` anger. TTL för nonce i Valkey i BFF måste vara >= TTL för en opaque session i HsmWorker.

## Motivering

Varje försök att byta ut nonce bryter jws-signaturen, vilket hsm-worker avvisar i fas 1 av JWS-verifieringen. Signaturbindningen gör attacker kryptografiskt detekterbara utan att lägga verifieringsansvar på BFF:en.

Följande alternativ övervägdes och avvisades:

- **Tidsstämpel (`issued_at`) vid sidan av nonce** – skulle stänga fönstret för replay efter Valkey TTL-utgång, men den extra komplexiteten (nytt fält i `OuterRequest`, ny konfigvariabel `REPLAY_WINDOW_SECONDS`, tidsstämpelvalidering i workern) bedömdes inte motiverad av hotbilden. Session-JWE-operationer skyddas redan av att den efemära sessionsnyckeln försvinner vid omstart; Device-JWE-operationer har ett reellt men begränsat fönster tack vare att OPAQUE är ett protokoll som utförs i två steg.

- **Skydd för state-init** – `/hsm/v1/device-states` är work-in-progress och saknar i nuläget signerad payload och klientnyckel. Vi får återkomma till skydd av denna endpoint när vi vet hur den ska se ut. 

## Konsekvenser av beslutet

- Replay-attacker mot nonce är kryptografiskt detekterbara – manipulation bryter jws-signaturen.
- BFF:en validerar inte nonce-formatet; unicitet inom TTL-fönstret är det enda serverinvarianten.
- Valkey-deduplicering består över ev. omstart av hsm-worker och täcker replay av Device-JWE-operationer där serverns statiska ECDH-ES-nyckel överlever omstart.
- Nonce-namnrymden per `client_id` förhindrar kollisioner mellan olika klienter men ger inte skydd mot DoS – lämplig åtgärd mot nonce-flooding är hastighetsbegränsning på HTTP-lagret.
- `/hsm/v1/device-states` (state-init) är undantaget från nonce-baserat skydd.
