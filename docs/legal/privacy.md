# Privacy Policy

Effective: on publication at www.wrendns.com
Last updated: 19 November 2026

<!-- DRAFT adapted from the MySummitKeep LLC Privacy Policy (www.mysummitkeep.com/privacy), for the owner and counsel to review before launch. Values to confirm are marked [confirm]. Every statement about the website and the software must stay true: re-check it whenever the site adds a script, or the software adds an outbound connection. -->

MySummitKeep LLC ("we", "us" or "our") makes WrenDNS and runs the website at www.wrendns.com and wrendns.com (the "Site"). This policy describes what information we collect through the Site, through Support Payments and through support email, how we use it, who we disclose it to, and how we protect it. It also explains what the WrenDNS software (the "Software") does with information, because the Software runs on your network rather than on ours.

## 1. Notice at collection

We collect the categories of personal information in section 2 for the purposes in section 4, and keep them for the periods in section 7. We do not sell your personal information. We do not "share" it for cross-context behavioural advertising, as those terms are defined under California law. This section is our notice at collection under California Civil Code section 1798.100(b).

## 2. Information we collect

### 2.1 When you visit the Site

- **No cookies, analytics or tracking.** The Site sets no cookies. It loads no analytics, advertising, session-replay or tracking scripts, and we do not build profiles of visitors.
- **Server logs.** Our host, Microsoft Azure (Azure Static Web Apps), receives each request's IP address, browser user agent, the page requested and the time, as any web server does. It uses them to deliver the Site and protect it from abuse. We do not use this data to identify visitors. [confirm the Azure log settings and their retention]

### 2.2 When you make a Support Payment

Payments are made on Stripe's checkout page. Stripe collects your card or other payment details, your email address, and any billing details its checkout asks for. We receive from Stripe your name, your email address, the amount, the date, whether the payment is one-time or monthly, your billing country and postal code if Stripe collects them, and the card brand and last four digits. **We never receive or store your full card number.**

### 2.3 When you email us

When you write to support@wrendns.com, we receive your email address, your name if you include it, and whatever you choose to tell us.

### 2.4 Minors

The Site, Support Payments and support are for adults. They are not directed at anyone under eighteen (18), and we do not knowingly collect personal information from anyone under eighteen. If we learn that we have, we delete it. If you believe a minor has sent us personal information, contact support@wrendns.com.

## 3. The WrenDNS software and your information

The Software runs on devices you control, such as a Raspberry Pi, a server or a Kubernetes cluster. It keeps its data there: DNS queries and answers, device names, the network inventory, the CMDB, and, if you enable the browser and endpoint agent, browsing history. **None of it is sent to MySummitKeep LLC.** We never receive it, including any data about minors who use devices on your network. You decide what it records and for how long, and you are responsible for how you use that data, including the laws on monitoring the people and devices on your network.

The Software makes its own outbound connections only for features you can control:

- **Update check.** Once a day it reads a signed list of WrenDNS releases from GitHub, which GitHub serves and which shows GitHub your node's IP address. Turn it off with `[updates] check = false`.
- **Downloads you configure.** It fetches the blocklists, the GeoIP database and the category sources you select, from the providers you select.
- **Services you connect.** It reads routers, Home Assistant and SNMP devices, and sends telemetry to the export targets (OTLP, webhooks, alert sinks) you configure.
- **DNS.** It forwards lookups to the upstream resolvers you choose.

Each of these goes to the provider you configured, not to us.

## 4. How we use information

- To process Support Payments, send receipts, and manage and cancel monthly Support Payments.
- To answer support requests and other messages.
- To deliver the Site and protect it from fraud, abuse and security threats.
- To meet legal, tax and accounting obligations, and to enforce our Terms of Service.

We do not use your personal information for advertising, for profiling that produces legal or similarly significant effects, or to train any AI model.

## 5. Who we disclose information to

We do not sell, rent or trade your personal information. We disclose it only as follows:

| Recipient | Purpose |
|---|---|
| Stripe, Inc. | Processing Support Payments, receipts and cancellations |
| Microsoft Azure | Hosting the Site |
| Microsoft 365 (Exchange Online) | Receiving and answering support email |
| GitHub, Inc. | Hosting the source code and downloads. GitHub receives the request data of anyone who downloads from it, under GitHub's own privacy statement |
| Legal authorities | When required by law, legal process or a government request |
| Acquirers | In a merger, acquisition, bankruptcy or sale of assets, with notice to you |

Each service provider acts under contractual obligations that limit its use of personal information to the purpose above.

## 6. Security

- Information is encrypted in transit (TLS 1.2 or later) and at rest by our providers.
- Access to payment and support data is limited to the people who need it, using multi-factor authentication.
- Card details are handled only by Stripe, which is certified to PCI DSS Level 1.
- The Site is served over HTTPS only, with security headers.

No method of transmission or storage is 100% secure.

## 7. Retention

| Category | Kept for |
|---|---|
| Support Payment records | 7 years (tax and audit) |
| Support email | 3 years after the last message in a conversation [confirm] |
| Site server logs | As long as our host keeps them [confirm, and keep it short] |

## 8. Your rights and choices

You may ask us to give you a copy of, correct, or delete the personal information we hold about you, or to provide it in a structured, machine-readable format. Email privacy@wrendns.com. We respond to verifiable requests within forty-five (45) days, extendable by another forty-five (45) days with notice. You may appeal a denial by replying to our response. We will not discriminate against you for exercising these rights. We may keep payment records that the law requires us to keep.

Depending on where you live, you may have more rights under a state privacy law, for example in California, Virginia, Colorado, Connecticut, Texas, Oregon or Florida. We grant these rights to every U.S. consumer, whatever their state, and you may complain to your state's Attorney General where the law allows.

## 9. Global Privacy Control

We honour Global Privacy Control signals as a request to opt out of sale and sharing. We do not sell or share personal information, so a signal changes nothing in practice.

## 10. International visitors

The Site and our records are hosted in the United States. If you visit from elsewhere, your information is transferred to and processed in the United States.

## 11. Third-party links

The Site links to other websites, including GitHub and Stripe. We are not responsible for their privacy practices. Please read their policies.

## 12. Changes to this policy

We may update this policy. Material changes are posted on the Site with a new "Last updated" date. If you have an active monthly Support Payment, we also email you about them. We review this policy at least once every twelve (12) months, and whenever the Site or the Software adds a new way of handling information.

## 13. Contact us

MySummitKeep LLC (WrenDNS), Attn: Privacy
5005 W Laurel St, Ste 100 #3250
Tampa, FL 33607
Phone: (813) 418-6800
Privacy: privacy@wrendns.com
General: support@wrendns.com
