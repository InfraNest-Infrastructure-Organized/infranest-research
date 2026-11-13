/*
 * Who provides what, for the provider measures of InfraNest Research
 * (summarise-cc-security.mjs). One company often has several roles — Microsoft
 * receives mail (MX), sends it (SPF), hosts DNS and runs a cloud — so each role
 * is matched separately, on the evidence that role leaves in public DNS:
 *
 *   mail     MX host suffix              dns      NS host suffix
 *   sending  SPF include domain suffix   web      network (ASN) name of the site's IPv4 address
 *   reports  DMARC rua domain suffix     issuer   certificate issuer organisation
 *
 * `hq` is the country of the headquarters of the company that OPERATES the
 * service (ISO 3166) — not its parent group (Mailjet is run from Paris although
 * Sinch owns it). It describes the company, not where a given server runs, and
 * is the basis for the "where are the providers based" measures (US / EU /
 * rest of Europe / other). `cdn: true` marks a proxy/CDN: a site "behind"
 * it is not necessarily hosted there.
 *
 * Version 1 (November 2026): the large international providers plus the main
 * hosts and registrars of NL, DE and FR. Unmatched values are listed by the
 * summariser ("unmatched") so the table can be extended after a dry run; a
 * change here needs no rescan. Matching: host roles by domain suffix, network
 * names by whole word, issuers by substring; longest pattern first.
 */

export const PROVIDERS = [
  // --- international
  { name: 'Microsoft', hq: 'US', mail: ['mail.protection.outlook.com', 'mx.microsoft', 'outlook.com', 'hotmail.com'], sending: ['spf.protection.outlook.com', 'protection.outlook.com'], dns: ['azure-dns.com', 'azure-dns.net', 'azure-dns.org', 'azure-dns.info'], web: ['MICROSOFT'], issuer: ['Microsoft'] },
  { name: 'Google', hq: 'US', mail: ['google.com', 'googlemail.com', 'aspmx.l.google.com'], sending: ['_spf.google.com', 'google.com'], dns: ['googledomains.com', 'google.com'], web: ['GOOGLE'], issuer: ['Google Trust Services'] },
  { name: 'Amazon', hq: 'US', mail: ['amazonaws.com', 'awsapps.com'], sending: ['amazonses.com'], dns: ['awsdns-'], web: ['AMAZON'], issuer: ['Amazon'] },
  { name: 'Cloudflare', hq: 'US', cdn: true, mail: ['mx.cloudflare.net', 'cf-emailsecurity.net'], sending: ['_spf.mx.cloudflare.net'], dns: ['ns.cloudflare.com', 'cloudflare.com', 'foundationdns.com', 'foundationdns.net', 'foundationdns.org'], web: ['CLOUDFLARENET', 'CLOUDFLARESPECTRUM', 'CLOUDFLARE'], reports: ['dmarc-reports.cloudflare.net', 'cloudflare.net'], issuer: ['Cloudflare'] },
  { name: 'Akamai', hq: 'US', cdn: true, dns: ['akam.net', 'akamaiedge.net'], web: ['AKAMAI'] },
  { name: 'Linode (Akamai)', hq: 'US', web: ['LINODE'] },
  { name: 'Fastly', hq: 'US', cdn: true, web: ['FASTLY'] },
  { name: 'DigitalOcean', hq: 'US', dns: ['digitalocean.com'], web: ['DIGITALOCEAN'] },
  { name: 'Oracle', hq: 'US', dns: ['oraclecloud.net', 'dynect.net'], sending: ['oracleemaildelivery.com', 'oraclecloud.com'], web: ['ORACLE'] },
  { name: 'GoDaddy', hq: 'US', mail: ['secureserver.net'], sending: ['secureserver.net'], dns: ['domaincontrol.com'], web: ['GODADDY'], issuer: ['GoDaddy'] },
  { name: 'Vercara (UltraDNS)', hq: 'US', dns: ['ultradns.com', 'ultradns.net', 'ultradns.org', 'ultradns.biz'] },
  { name: 'NS1 (IBM)', hq: 'US', dns: ['nsone.net'] },
  { name: 'MarkMonitor', hq: 'US', dns: ['markmonitor.com'] },
  { name: 'CSC', hq: 'US', dns: ['cscdns.net', 'cscdns.uk', 'netnames.net'] },
  { name: 'Namecheap', hq: 'US', dns: ['registrar-servers.com'] },
  { name: 'Broadcom (Symantec Email)', hq: 'US', mail: ['messagelabs.com'] },
  { name: 'Automattic', hq: 'US', mail: ['automattic.com'], web: ['AUTOMATTIC'] },
  { name: 'Proofpoint', hq: 'US', mail: ['pphosted.com', 'ppe-hosted.com'], sending: ['pphosted.com'], reports: ['emaildefense.proofpoint.com'] },
  { name: 'Cisco Secure Email', hq: 'US', mail: ['iphmx.com'], sending: ['iphmx.com'] },
  { name: 'Barracuda', hq: 'US', mail: ['barracudanetworks.com', 'ess.barracudanetworks.com'] },
  { name: 'N-able Mail Assure', hq: 'US', mail: ['antispamcloud.com', 'spamexperts.com', 'spamexperts.eu', 'spamexperts.net'], sending: ['spamexperts.com', 'antispamcloud.com'] },
  { name: 'Mimecast', hq: 'GB', mail: ['mimecast.com', 'mimecast.co.za'], sending: ['mimecast.com', 'mim.ec'], reports: ['dmarc-analyzer.com', 'dmarcanalyzer.com', 'mimecastdmarcanalyzer.com', 'mimecast.com'] },
  { name: 'Twilio SendGrid', hq: 'US', sending: ['sendgrid.net'] },
  { name: 'Mailgun', hq: 'US', mail: ['mailgun.org'], sending: ['mailgun.org'] },
  { name: 'Mailchimp (Intuit)', hq: 'US', sending: ['servers.mcsv.net', 'mandrillapp.com', 'mcsv.net'] },
  { name: 'Postmark', hq: 'US', sending: ['spf.mtasv.net', 'mtasv.net'] },
  { name: 'Salesforce', hq: 'US', sending: ['_spf.salesforce.com', 'exacttarget.com', 'salesforce.com'] },
  { name: 'HubSpot', hq: 'US', sending: ['hubspotemail.net'] },
  { name: 'Zendesk', hq: 'US', sending: ['mail.zendesk.com', 'zendesk.com'] },
  { name: 'Freshworks', hq: 'US', sending: ['freshdesk.com', 'freshemail.io'] },
  { name: 'Atlassian', hq: 'US', sending: ['atlassian.net', '_spf.atlassian.net'] },
  { name: 'Zoho', hq: 'IN', mail: ['zoho.com', 'zoho.eu', 'zohomail.com', 'zohomail.eu'], sending: ['zoho.com', 'zoho.eu', 'zcsend.net'] },
  { name: 'Fastmail', hq: 'AU', mail: ['messagingengine.com'], sending: ['messagingengine.com'] },
  { name: 'Wix', hq: 'IL', dns: ['wixdns.net'], web: ['WIX'] },
  { name: 'Shopify', hq: 'CA', sending: ['shops.shopify.com'], web: ['SHOPIFY'] },
  { name: 'Squarespace', hq: 'US', dns: ['squarespacedns.com'], web: ['SQUARESPACE'] },
  { name: 'dmarcian', hq: 'US', reports: ['dmarcian.com', 'dmarcian.eu', 'dmarcian-eu.com'] },
  { name: 'Valimail', hq: 'US', reports: ['valimail.com', 'vali.email'] },
  { name: 'Agari (Fortra)', hq: 'US', reports: ['agari.com'] },
  { name: 'EasyDMARC', hq: 'AM', reports: ['easydmarc.com', 'easydmarc.us', 'easydmarc.eu'] },
  { name: 'PowerDMARC', hq: 'US', reports: ['powerdmarc.com'] },
  { name: 'Validity (Everest, 250ok)', hq: 'US', reports: ['everest.email', '250ok.net'] },
  { name: 'Imperva', hq: 'US', cdn: true, web: ['INCAPSULA', 'IMPERVA'] },
  { name: 'Red Sift', hq: 'GB', reports: ['ondmarc.com', 'redsift.cloud'] },
  { name: 'Postmark DMARC', hq: 'US', reports: ['dmarc.postmarkapp.com'] },
  { name: "Let's Encrypt (ISRG)", hq: 'US', issuer: ["Let's Encrypt"] },
  { name: 'DigiCert', hq: 'US', issuer: ['DigiCert'] },
  { name: 'Sectigo', hq: 'US', issuer: ['Sectigo', 'COMODO'] },
  { name: 'Entrust', hq: 'US', issuer: ['Entrust'] },
  { name: 'SSL.com', hq: 'US', issuer: ['SSL Corporation', 'SSL.com'] },
  { name: 'GlobalSign', hq: 'BE', issuer: ['GlobalSign'] },
  { name: 'Deutsche Telekom Security', hq: 'DE', issuer: ['Deutsche Telekom Security'] },
  { name: 'Gandi (CA)', hq: 'FR', issuer: ['Gandi'] },
  // --- European
  { name: 'Hetzner', hq: 'DE', mail: ['your-server.de', 'hetzner.com', 'hetzner.company'], sending: ['hetzner.com'], dns: ['your-server.de', 'second-ns.com', 'second-ns.de', 'hetzner.com', 'hetzner.de', 'first-ns.de'], web: ['HETZNER'] },
  { name: 'IONOS', hq: 'DE', mail: ['ionos.de', 'ionos.com', 'kundenserver.de', 'perfora.net', '1and1.com', 'schlund.de'], sending: ['_spf.perfora.net', '_spf.kundenserver.de', 'ionos.de', 'ionos.com'], dns: ['ui-dns.de', 'ui-dns.com', 'ui-dns.org', 'ui-dns.biz'], web: ['IONOS', '1&1', 'ONEANDONE'] },
  { name: 'Strato', hq: 'DE', mail: ['rzone.de', 'strato.de'], sending: ['strato.de', 'rzone.de'], dns: ['rzone.de', 'strato.de'], web: ['STRATO'] },
  { name: 'All-Inkl', hq: 'DE', mail: ['kasserver.com'], sending: ['kasserver.com'], dns: ['kasserver.com', 'all-inkl.com'], web: ['ALL-INKL', 'NEUE MEDIEN MUENNICH'] },
  { name: 'Mittwald', hq: 'DE', mail: ['mittwald.de', 'agenturserver.de', 'agenturserver.co', 'agenturserver.it'], dns: ['mittwald.de', 'agenturserver.de', 'agenturserver.co', 'agenturserver.it'], web: ['MITTWALD'] },
  { name: 'netcup', hq: 'DE', mail: ['netcup.net'], dns: ['netcup.net'], web: ['NETCUP'] },
  { name: 'Contabo', hq: 'DE', web: ['CONTABO'] },
  { name: 'Hornetsecurity', hq: 'DE', mail: ['hornetsecurity.com', 'hornetsecurity.net'], sending: ['hornetsecurity.com', 'spf.hornetsecurity.com'] },
  { name: 'Retarus', hq: 'DE', mail: ['retarus.com', 'retarus.net', 'retarus.de'], sending: ['retarus.com'] },
  { name: 'Sedo (parking)', hq: 'DE', dns: ['sedoparking.com'], web: ['SEDO'] },
  { name: 'OVHcloud', hq: 'FR', mail: ['ovh.net', 'mail.ovh.net'], sending: ['mx.ovh.com', 'ovh.com'], dns: ['ovh.net', 'anycast.me', 'ovh.ca'], web: ['OVH'] },
  { name: 'Gandi', hq: 'FR', mail: ['gandi.net'], sending: ['_mailcust.gandi.net', 'gandi.net'], dns: ['gandi.net', 'gandi-ns.fr'], web: ['GANDI'] },
  { name: 'Scaleway', hq: 'FR', dns: ['scw.cloud'], web: ['SCALEWAY', 'ONLINE S.A.S', 'ONLINE SAS'] },
  { name: 'Orange', hq: 'FR', mail: ['orange.fr', 'orange-business.com'], web: ['ORANGE'] },
  { name: 'Brevo', hq: 'FR', sending: ['spf.brevo.com', 'spf.sendinblue.com', 'sendinblue.com', 'brevo.com'], reports: ['brevo.com'] },
  { name: 'Mailjet (Sinch)', hq: 'FR', sending: ['spf.mailjet.com', 'mailjet.com'] },
  { name: 'MailerLite', hq: 'LT', sending: ['_spf.mlsend.com', 'mlsend.com'] },
  { name: 'Hostinger', hq: 'LT', mail: ['hostinger.com'], sending: ['_spf.mail.hostinger.com'], dns: ['dns-parking.com', 'hostinger.com'], web: ['HOSTINGER'] },
  { name: 'TransIP', hq: 'NL', mail: ['transip.email', 'transip.nl'], sending: ['_spf.transip.email', 'transip.email'], dns: ['transip.net', 'transip.nl', 'transip.eu'], web: ['TRANSIP'] },
  { name: 'Hostnet', hq: 'NL', mail: ['hostnet.nl'], sending: ['hostnet.nl'], dns: ['hostnet.nl'], web: ['HOSTNET'] },
  { name: 'Antagonist', hq: 'NL', mail: ['antagonist.nl'], dns: ['antagonist.nl'], web: ['ANTAGONIST'] },
  { name: 'Mijndomein', hq: 'NL', mail: ['mijndomein.nl'], dns: ['mijndomein.nl'] },
  { name: 'Openprovider', hq: 'NL', dns: ['openprovider.nl', 'openprovider.be', 'openprovider.eu'] },
  { name: 'Leaseweb', hq: 'NL', web: ['LEASEWEB'] },
  { name: 'Combell', hq: 'BE', mail: ['combell.net'], dns: ['combell.net', 'combell.com'], web: ['COMBELL'] },
  { name: 'URIports', hq: 'NL', reports: ['uriports.com'] },
  { name: 'DMARC Advisor', hq: 'NL', reports: ['dmarcadvisor.com'] },
  { name: 'Copernica (SMTPeter)', hq: 'NL', sending: ['smtpeter.com'], reports: ['smtpeter.com'] },
  { name: 'Spotler (Flowmailer)', hq: 'NL', sending: ['flowmailer.net'], reports: ['flowmailer.net'] },
  { name: 'SURF', hq: 'NL', mail: ['surfmailfilter.nl', 'surf.nl', 'surfnet.nl'], dns: ['surfnet.nl', 'surf.net', 'surf.nl'], web: ['SURFNET-NL', 'SURF'] },
  // Network names: not the bare word KPN — AS286 is named "KPN - GTT Communications" (sold to GTT).
  { name: 'KPN', hq: 'NL', mail: ['kpnmail.nl', 'kpn.com', 'kpn.net'], dns: ['kpn.net', 'kpn.nl'], web: ['KPN B.V.', 'KPN-CORPORATE'], reports: ['kpnmail.nl'] },
  { name: 'VodafoneZiggo', hq: 'NL', mail: ['ziggo.nl', 'upcmail.net'], dns: ['upc.biz', 'ziggo.nl'], web: ['ZIGGO', 'VODAFONE LIBERTEL'], reports: ['ziggo.com', 'ziggo.nl'] },
  { name: 'DELTA Fiber', hq: 'NL', mail: ['zeelandnet.nl', 'delta.nl'], dns: ['zeelandnet.nl', 'delta.nl'], web: ['KABELFOON', 'DELTA FIBER'] },
  { name: 'Solcon', hq: 'NL', mail: ['solcon.nl'], dns: ['solcon.nl'], web: ['SOLCON'] },
  { name: 'Dutch government (DICTU / SSC-ICT)', hq: 'NL', mail: ['dictu.nl', 'minjenv.nl', 'minocw.nl', 'minvenj.nl', 'rijksoverheid.nl', 'ssonet.nl'], sending: ['ssonet.nl'], dns: ['rijksoverheidnl.com', 'rijksoverheidnl.nl', 'rijksoverheidnl.eu', 'rijksoverheidnl.org'], reports: ['minvenj.nl', 'minjenv.nl', 'rijksoverheid.nl', 'ssonet.nl'] },
  { name: 'NPO (Dutch public broadcasting)', hq: 'NL', dns: ['npohosting.nl', 'omroep.nl'], web: ['PUBLIEKE-OMROEP-AS'] },
  { name: 'SIDN', hq: 'NL', dns: ['sidn.nl', 'sidnlabs.nl'] },
  { name: 'Your Hosting', hq: 'NL', web: ['CLDIN-NL', 'YOUR HOSTING'] },
  { name: 'BIT', hq: 'NL', web: ['NL-BIT'] },
  { name: 'Previder', hq: 'NL', mail: ['previder.nl'], web: ['PREVIDER-AS', 'PREVIDER'] },
  { name: 'True (Fullstaq)', hq: 'NL', web: ['TRUESERVER-AS', 'TRUEFULLSTAQ'] },
  { name: 'Prolocation', hq: 'NL', mail: ['prolocation.nl', 'prolocation.net'], web: ['PROLOCATION'] },
  { name: 'Intermax', hq: 'NL', web: ['NL-INTERMAX', 'INTERMAX'] },
  { name: 'Duocast', hq: 'NL', web: ['DUOCAST-AS', 'DUOCAST'] },
  { name: 'Uniserver', hq: 'NL', web: ['UNISERVER-AS', 'UNISERVER'] },
  { name: 'Infopact', hq: 'NL', web: ['INFOPACT-AS', 'INFOPACT'] },
  { name: 'A2B Internet', hq: 'NL', web: ['A2B'] },
  { name: 'Webvalue', hq: 'NL', dns: ['ns-webvalue.nl'] },
  { name: 'Spamservice', hq: 'NL', mail: ['spamservice.nl'] },
  // one.com group, which now also runs Hostnet and Antagonist infrastructure.
  { name: 'one.com group', hq: 'DK', mail: ['one.com'], sending: ['g1i.one'], dns: ['one.com', 'g1-dns.com', 'g1-dns.one'], web: ['ONECOM', 'ONE.COM'], reports: ['g1i.one'] },
  { name: 'mailbox.org', hq: 'DE', mail: ['mailbox.org'], sending: ['mailbox.org'] },
  { name: '1&1 Versatel', hq: 'DE', dns: ['versatel.net', 'versatel.de'], web: ['VERSATEL'] },
  { name: 'ClouDNS', hq: 'BG', dns: ['cloudns.net'] },
  { name: 'HARICA', hq: 'GR', issuer: ['Hellenic Academic and Research Institutions'] },
  { name: 'Certum (Asseco)', hq: 'PL', issuer: ['Asseco', 'Unizeto', 'Certum'] },
  { name: 'Actalis', hq: 'IT', issuer: ['Actalis'] },
  { name: 'Buypass', hq: 'NO', issuer: ['Buypass'] },
  { name: 'ZeroSSL', hq: 'AT', issuer: ['ZeroSSL'] },
  { name: 'Infomaniak', hq: 'CH', mail: ['infomaniak.ch'], dns: ['infomaniak.ch'], web: ['INFOMANIAK'] },
  { name: 'Proton', hq: 'CH', mail: ['protonmail.ch', 'proton.me'], sending: ['_spf.protonmail.ch'] },
];

const EU = new Set(['AT', 'BE', 'BG', 'HR', 'CY', 'CZ', 'DK', 'EE', 'FI', 'FR', 'DE', 'GR', 'HU', 'IE', 'IT', 'LV', 'LT', 'LU', 'MT', 'NL', 'PL', 'PT', 'RO', 'SK', 'SI', 'ES', 'SE']);
const REST_OF_EUROPE = new Set(['GB', 'CH', 'NO', 'IS', 'LI']);

/** US | EU | Europe (non-EU) | other */
export function region(hq) {
  if (hq === 'self') return 'own domain';
  if (hq === 'US') return 'US';
  if (EU.has(hq)) return 'EU';
  if (REST_OF_EUROPE.has(hq)) return 'Europe (non-EU)';
  return 'other';
}

// Longest pattern first, so "spf.protection.outlook.com" beats "outlook.com".
const index = {};
for (const role of ['mail', 'sending', 'dns', 'reports', 'web', 'issuer']) {
  index[role] = PROVIDERS.flatMap((p) => (p[role] ?? []).map((pat) => ({ pat: pat.toLowerCase(), p }))).sort((a, b) => b.pat.length - a.pat.length);
}

const suffixMatch = (value, pat) => value === pat || value.endsWith(`.${pat}`) || (pat.endsWith('-') && value.includes(pat));
const esc = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
// Network names: whole words only, so "OVH" does not match inside "GOVHOST".
const wordMatch = (value, pat) => new RegExp(`(^|[^a-z0-9])${esc(pat)}([^a-z0-9]|$)`).test(value);

/** The provider for one value in one role, or null. Host roles match by suffix; network names by whole word; issuers by substring. */
export function providerFor(role, value) {
  if (!value) return null;
  const v = String(value).toLowerCase().replace(/\.$/, '');
  const match = role === 'web' ? wordMatch : role === 'issuer' ? (x, p) => x.includes(p) : suffixMatch;
  return index[role].find(({ pat }) => match(v, pat))?.p ?? null;
}

/** The registrable-looking tail of a host name, for listing unmatched values (example.co.uk is close enough). */
export function tail(host) {
  return String(host).toLowerCase().replace(/\.$/, '').split('.').slice(-2).join('.');
}
