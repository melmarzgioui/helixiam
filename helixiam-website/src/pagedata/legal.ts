import type { Locale } from "../i18n";
export interface LegalDoc { metaTitle: string; metaDesc: string; updated: string; bodyHtml: string; }

// Legal prose per locale. [bracketed] placeholders are left for legal counsel to complete (untranslated).
export const privacy: Record<Locale, LegalDoc> = {
  en: {
    metaTitle: "Privacy Policy", updated: "2026",
    metaDesc: "How HelixIAM handles personal data on helixiam.com.",
    bodyHtml: `<p>This Privacy Policy explains how <strong>[HelixIAM legal entity]</strong> ("HelixIAM", "we", "us") processes personal data in connection with the <strong>helixiam.com</strong> website and our sales and support activities. It does not describe data processed <em>within</em> a self-hosted HelixIAM deployment you operate — you are the controller of that data.</p>
<h2>Who we are</h2>
<p>HelixIAM is a product of <strong>[HelixIAM legal entity, address, registration number]</strong>, based in Europe. For privacy questions, contact <strong>[privacy@helixiam.com]</strong>.</p>
<h2>What we collect</h2>
<ul>
  <li><strong>Contact &amp; demo requests</strong> — name, work email, company, role and message you submit via our forms.</li>
  <li><strong>Usage data</strong> — privacy-respecting, aggregated analytics about site usage (no cross-site tracking).</li>
  <li><strong>Communications</strong> — emails and messages you send us.</li>
</ul>
<h2>Why we process it</h2>
<ul>
  <li>To respond to demo and contact requests (legitimate interest / pre-contract steps).</li>
  <li>To provide and improve the website (legitimate interest).</li>
  <li>To send you information you asked for (consent).</li>
</ul>
<h2>Legal basis &amp; your rights</h2>
<p>We process personal data under the GDPR. You have the right to access, rectify, erase, restrict, and port your data, and to object to processing. To exercise these rights, contact <strong>[privacy@helixiam.com]</strong>. You may also lodge a complaint with your local supervisory authority.</p>
<h2>Sharing &amp; retention</h2>
<p>We share personal data only with processors that help us operate (e.g. hosting, CRM, email), under data-processing agreements, and we keep data in the EU where feasible. We retain contact data only as long as necessary for the purposes above.</p>
<h2>Cookies</h2>
<p>We aim to keep the site cookie-light and free of third-party advertising trackers. Where cookies are used, we describe them and obtain consent as required.</p>
<h2>Changes</h2>
<p>We may update this policy; material changes will be reflected in the "last updated" date above.</p>`,
  },
  fr: {
    metaTitle: "Politique de confidentialité", updated: "2026",
    metaDesc: "Comment HelixIAM traite les données personnelles sur helixiam.com.",
    bodyHtml: `<p>Cette Politique de confidentialité explique comment <strong>[entité juridique HelixIAM]</strong> (« HelixIAM », « nous ») traite les données personnelles dans le cadre du site <strong>helixiam.com</strong> et de nos activités commerciales et de support. Elle ne décrit pas les données traitées <em>au sein</em> d'un déploiement HelixIAM auto-hébergé que vous exploitez — vous êtes le responsable du traitement de ces données.</p>
<h2>Qui nous sommes</h2>
<p>HelixIAM est un produit de <strong>[entité juridique HelixIAM, adresse, numéro d'immatriculation]</strong>, basée en Europe. Pour toute question relative à la confidentialité, contactez <strong>[privacy@helixiam.com]</strong>.</p>
<h2>Ce que nous collectons</h2>
<ul>
  <li><strong>Demandes de contact &amp; de démo</strong> — nom, e-mail professionnel, entreprise, rôle et message que vous soumettez via nos formulaires.</li>
  <li><strong>Données d'utilisation</strong> — statistiques agrégées et respectueuses de la vie privée sur l'utilisation du site (aucun suivi inter-sites).</li>
  <li><strong>Communications</strong> — e-mails et messages que vous nous envoyez.</li>
</ul>
<h2>Pourquoi nous les traitons</h2>
<ul>
  <li>Pour répondre aux demandes de démo et de contact (intérêt légitime / démarches précontractuelles).</li>
  <li>Pour fournir et améliorer le site (intérêt légitime).</li>
  <li>Pour vous envoyer les informations que vous avez demandées (consentement).</li>
</ul>
<h2>Base légale &amp; vos droits</h2>
<p>Nous traitons les données personnelles conformément au RGPD. Vous disposez d'un droit d'accès, de rectification, d'effacement, de limitation et de portabilité de vos données, ainsi que d'un droit d'opposition au traitement. Pour exercer ces droits, contactez <strong>[privacy@helixiam.com]</strong>. Vous pouvez également introduire une réclamation auprès de votre autorité de contrôle locale.</p>
<h2>Partage &amp; conservation</h2>
<p>Nous ne partageons les données personnelles qu'avec des sous-traitants qui nous aident à fonctionner (p. ex. hébergement, CRM, e-mail), dans le cadre d'accords de traitement des données, et nous conservons les données dans l'UE lorsque cela est possible. Nous ne conservons les données de contact que le temps nécessaire aux finalités ci-dessus.</p>
<h2>Cookies</h2>
<p>Nous nous efforçons de limiter les cookies sur le site et d'éviter les traceurs publicitaires tiers. Lorsque des cookies sont utilisés, nous les décrivons et recueillons le consentement requis.</p>
<h2>Modifications</h2>
<p>Nous pouvons mettre à jour cette politique ; les modifications importantes seront reflétées dans la date de « dernière mise à jour » ci-dessus.</p>`,
  },
  nl: {
    metaTitle: "Privacybeleid", updated: "2026",
    metaDesc: "Hoe HelixIAM omgaat met persoonsgegevens op helixiam.com.",
    bodyHtml: `<p>Dit Privacybeleid legt uit hoe <strong>[juridische entiteit HelixIAM]</strong> ("HelixIAM", "wij", "ons") persoonsgegevens verwerkt in verband met de website <strong>helixiam.com</strong> en onze verkoop- en supportactiviteiten. Het beschrijft niet de gegevens die worden verwerkt <em>binnen</em> een zelf-gehoste HelixIAM-omgeving die je beheert — jij bent de verwerkingsverantwoordelijke voor die gegevens.</p>
<h2>Wie we zijn</h2>
<p>HelixIAM is een product van <strong>[juridische entiteit HelixIAM, adres, registratienummer]</strong>, gevestigd in Europa. Voor privacyvragen kun je contact opnemen via <strong>[privacy@helixiam.com]</strong>.</p>
<h2>Wat we verzamelen</h2>
<ul>
  <li><strong>Contact- &amp; demo-aanvragen</strong> — naam, zakelijk e-mailadres, bedrijf, rol en bericht die je via onze formulieren indient.</li>
  <li><strong>Gebruiksgegevens</strong> — privacyvriendelijke, geaggregeerde analyses over het sitegebruik (geen cross-site tracking).</li>
  <li><strong>Communicatie</strong> — e-mails en berichten die je ons stuurt.</li>
</ul>
<h2>Waarom we ze verwerken</h2>
<ul>
  <li>Om te reageren op demo- en contactaanvragen (gerechtvaardigd belang / precontractuele stappen).</li>
  <li>Om de website te leveren en te verbeteren (gerechtvaardigd belang).</li>
  <li>Om je informatie te sturen waar je om hebt gevraagd (toestemming).</li>
</ul>
<h2>Rechtsgrond &amp; je rechten</h2>
<p>We verwerken persoonsgegevens onder de AVG. Je hebt het recht op inzage, rectificatie, verwijdering, beperking en overdraagbaarheid van je gegevens, en het recht om bezwaar te maken tegen de verwerking. Om deze rechten uit te oefenen, neem contact op via <strong>[privacy@helixiam.com]</strong>. Je kunt ook een klacht indienen bij je lokale toezichthoudende autoriteit.</p>
<h2>Delen &amp; bewaren</h2>
<p>We delen persoonsgegevens alleen met verwerkers die ons helpen bij onze bedrijfsvoering (bijv. hosting, CRM, e-mail), onder verwerkersovereenkomsten, en we bewaren gegevens waar mogelijk in de EU. We bewaren contactgegevens niet langer dan nodig is voor de bovengenoemde doeleinden.</p>
<h2>Cookies</h2>
<p>We streven ernaar de site cookie-arm en vrij van externe advertentietrackers te houden. Waar cookies worden gebruikt, beschrijven we ze en vragen we waar vereist toestemming.</p>
<h2>Wijzigingen</h2>
<p>We kunnen dit beleid bijwerken; belangrijke wijzigingen worden weergegeven in de datum "laatst bijgewerkt" hierboven.</p>`,
  },
};

export const terms: Record<Locale, LegalDoc> = {
  en: {
    metaTitle: "Terms of Use", updated: "2026",
    metaDesc: "Terms governing use of the helixiam.com website.",
    bodyHtml: `<p>These Terms of Use govern your use of the <strong>helixiam.com</strong> website operated by <strong>[HelixIAM legal entity]</strong> ("HelixIAM", "we"). By using the site you agree to these terms. Use of the HelixIAM software itself is governed by a separate license and/or subscription agreement.</p>
<h2>Use of the site</h2>
<ul>
  <li>The content on this site is provided for general information about the HelixIAM product.</li>
  <li>You may not misuse the site, attempt to disrupt it, or access it in violation of applicable law.</li>
  <li>Trademarks, logos and content are owned by HelixIAM or its licensors.</li>
</ul>
<h2>No warranty</h2>
<p>The website is provided "as is" without warranties of any kind. Product capabilities described here reflect our current offering and may evolve; nothing on this site is a binding commitment or part of a contract unless expressly agreed in writing.</p>
<h2>Limitation of liability</h2>
<p>To the maximum extent permitted by law, HelixIAM is not liable for any indirect or consequential damages arising from your use of the website.</p>
<h2>Product terms</h2>
<p>Downloading, deploying, or subscribing to HelixIAM is subject to the applicable <strong>[license / subscription agreement]</strong>, which takes precedence over these website terms for any conflict relating to the software.</p>
<h2>Governing law</h2>
<p>These terms are governed by the laws of <strong>[the Netherlands / applicable EU jurisdiction]</strong>, without regard to conflict-of-laws rules.</p>
<h2>Contact</h2>
<p>Questions about these terms: <strong>[legal@helixiam.com]</strong>.</p>`,
  },
  fr: {
    metaTitle: "Conditions d'utilisation", updated: "2026",
    metaDesc: "Conditions régissant l'utilisation du site helixiam.com.",
    bodyHtml: `<p>Ces Conditions d'utilisation régissent votre utilisation du site <strong>helixiam.com</strong> exploité par <strong>[entité juridique HelixIAM]</strong> (« HelixIAM », « nous »). En utilisant le site, vous acceptez ces conditions. L'utilisation du logiciel HelixIAM lui-même est régie par un contrat de licence et/ou d'abonnement distinct.</p>
<h2>Utilisation du site</h2>
<ul>
  <li>Le contenu de ce site est fourni à titre d'information générale sur le produit HelixIAM.</li>
  <li>Vous ne pouvez pas détourner le site, tenter de le perturber ou y accéder en violation de la loi applicable.</li>
  <li>Les marques, logos et contenus sont la propriété de HelixIAM ou de ses concédants.</li>
</ul>
<h2>Absence de garantie</h2>
<p>Le site est fourni « tel quel », sans garantie d'aucune sorte. Les capacités du produit décrites ici reflètent notre offre actuelle et peuvent évoluer ; rien sur ce site ne constitue un engagement contraignant ou une partie d'un contrat, sauf accord écrit exprès.</p>
<h2>Limitation de responsabilité</h2>
<p>Dans toute la mesure permise par la loi, HelixIAM n'est pas responsable des dommages indirects ou consécutifs découlant de votre utilisation du site.</p>
<h2>Conditions du produit</h2>
<p>Le téléchargement, le déploiement ou l'abonnement à HelixIAM est soumis au <strong>[contrat de licence / d'abonnement]</strong> applicable, qui prévaut sur ces conditions du site en cas de conflit relatif au logiciel.</p>
<h2>Droit applicable</h2>
<p>Ces conditions sont régies par le droit <strong>[des Pays-Bas / de la juridiction UE applicable]</strong>, sans égard aux règles de conflit de lois.</p>
<h2>Contact</h2>
<p>Questions concernant ces conditions : <strong>[legal@helixiam.com]</strong>.</p>`,
  },
  nl: {
    metaTitle: "Gebruiksvoorwaarden", updated: "2026",
    metaDesc: "Voorwaarden voor het gebruik van de website helixiam.com.",
    bodyHtml: `<p>Deze Gebruiksvoorwaarden regelen je gebruik van de website <strong>helixiam.com</strong>, geëxploiteerd door <strong>[juridische entiteit HelixIAM]</strong> ("HelixIAM", "wij"). Door de site te gebruiken ga je akkoord met deze voorwaarden. Het gebruik van de HelixIAM-software zelf wordt geregeld door een afzonderlijke licentie- en/of abonnementsovereenkomst.</p>
<h2>Gebruik van de site</h2>
<ul>
  <li>De inhoud op deze site wordt verstrekt ter algemene informatie over het HelixIAM-product.</li>
  <li>Je mag de site niet misbruiken, verstoren of openen in strijd met toepasselijke wetgeving.</li>
  <li>Handelsmerken, logo's en inhoud zijn eigendom van HelixIAM of zijn licentiegevers.</li>
</ul>
<h2>Geen garantie</h2>
<p>De website wordt geleverd "zoals ze is", zonder enige garantie. De hier beschreven productmogelijkheden weerspiegelen ons huidige aanbod en kunnen evolueren; niets op deze site vormt een bindende toezegging of onderdeel van een contract, tenzij uitdrukkelijk schriftelijk overeengekomen.</p>
<h2>Beperking van aansprakelijkheid</h2>
<p>Voor zover maximaal toegestaan door de wet is HelixIAM niet aansprakelijk voor indirecte schade of gevolgschade die voortvloeit uit je gebruik van de website.</p>
<h2>Productvoorwaarden</h2>
<p>Het downloaden, implementeren of abonneren op HelixIAM is onderworpen aan de toepasselijke <strong>[licentie- / abonnementsovereenkomst]</strong>, die voorrang heeft op deze websitevoorwaarden bij een conflict met betrekking tot de software.</p>
<h2>Toepasselijk recht</h2>
<p>Deze voorwaarden worden beheerst door het recht van <strong>[Nederland / de toepasselijke EU-jurisdictie]</strong>, zonder rekening te houden met conflictregels.</p>
<h2>Contact</h2>
<p>Vragen over deze voorwaarden: <strong>[legal@helixiam.com]</strong>.</p>`,
  },
};
