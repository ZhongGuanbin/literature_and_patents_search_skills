from __future__ import annotations

"""Versioned, side-effect-free channel registry shared by search and download.

The tuples in this module are the compatibility boundary for channel display
names and order.  They intentionally describe the adapter that is actually
executed, including resolvers used after a nominal API/metadata step.
"""

from dataclasses import asdict, dataclass
import hashlib
import re
import unicodedata
from typing import Literal


REGISTRY_SCHEMA_VERSION = 2
REGISTRY_VERSION = "2026-07-19.3"

RecordType = Literal["literature", "patent"]


@dataclass(frozen=True, slots=True)
class Provider:
    provider_id: str
    display_name: str
    homepage: str
    capabilities: tuple[str, ...]

    @property
    def capability(self) -> tuple[str, ...]:
        return self.capabilities


@dataclass(frozen=True, slots=True)
class SearchAdapterSpec:
    adapter_id: str
    provider_id: str
    order: int
    display_name: str
    record_type: RecordType
    endpoint: str
    actual_adapter: str
    parser: str
    paths: tuple[str, ...]
    pagination: str
    query_fields: tuple[str, ...]
    required_locators: tuple[str, ...] = ("query:keyword",)
    required_locator_mode: Literal["any", "all"] = "all"
    auth_scope: str = "public"
    config_keys: tuple[str, ...] = ()
    optional_config_keys: tuple[str, ...] = ()
    fallback_resolver: str = ""
    capabilities: tuple[str, ...] = ("metadata_search",)
    cost: str = "free_or_provider_limited"
    default_enabled: bool = True
    # ``endpoint`` is the URL actually handed to ``actual_adapter``.  Keep the
    # nominal provider endpoint separately when an alias is implemented by a
    # different resolver (for example bioRxiv/medRxiv via Europe PMC).
    nominal_endpoint: str = ""
    # A fallback may have a different discovery credential scope from the
    # primary adapter.  Canonical locator provenance uses this value for
    # fallback-path observations instead of misattributing the primary scope.
    fallback_auth_scope: str = ""

    @property
    def capability(self) -> tuple[str, ...]:
        return self.capabilities

    @property
    def required_config_keys(self) -> tuple[str, ...]:
        return self.config_keys


@dataclass(frozen=True, slots=True)
class DownloadAdapterSpec:
    adapter_id: str
    provider_id: str
    order: int
    display_name: str
    record_type: RecordType
    endpoint: str
    actual_adapter: str
    required_locators: tuple[str, ...]
    required_locator_mode: Literal["any", "all"] = "any"
    auth_scope: str = "public"
    config_keys: tuple[str, ...] = ()
    optional_config_keys: tuple[str, ...] = ()
    fallback_resolver: str = ""
    capabilities: tuple[str, ...] = ("pdf_discovery",)
    cost: str = "free_or_provider_limited"
    default_enabled: bool = True

    @property
    def capability(self) -> tuple[str, ...]:
        return self.capabilities

    @property
    def required_config_keys(self) -> tuple[str, ...]:
        return self.config_keys


_PROVIDER_IDS = {
    "CNKI (中国知网)": "cnki",
    "万方数据": "wanfang",
    "度衍": "uyanip",
    "Sci-Hub": "sci_hub",
    "doi_resolver": "doi_resolver",
    "input_url": "input_url",
    "Crossref API": "crossref",
    "Crossref Metadata Search (search.crossref.org)": "crossref",
    "Semantic Scholar API": "semantic_scholar",
    "Semantic Scholar": "semantic_scholar",
    "SpringerLink": "springer_nature",
    "Springer": "springer_nature",
    "PMC (PubMed Central)": "ncbi",
    "PubMed": "ncbi",
}


def _slug(value: str) -> str:
    normalized = unicodedata.normalize("NFKD", value).encode("ascii", "ignore").decode()
    slug = re.sub(r"[^a-z0-9]+", "_", normalized.casefold()).strip("_")
    return slug or "provider_" + hashlib.sha256(value.encode("utf-8")).hexdigest()[:12]


def _provider_id(display_name: str) -> str:
    return _PROVIDER_IDS.get(display_name, _slug(display_name))


# display name, endpoint, runner, parser, paths, pagination, query fields,
# required config, optional config, auth scope, fallback, capabilities, cost
_LITERATURE_SEARCH_ROWS = (
    ("Web of Science Starter API (Clarivate)", "https://api.clarivate.com/apis/wos-starter/v1/documents", "search_wos_starter", "parse_wos_starter", ("api", "restricted_browser"), "page", ("TS",), ("CLARIVATE_API_KEY",), (), "web_of_science", "restricted_browser", ("metadata_search", "api", "restricted_web_fallback"), "provider_subscription"),
    ("IEEE Xplore API", "https://ieeexploreapi.ieee.org/api/v1/search/articles", "search_ieee", "parse_ieee_xplore", ("api", "restricted_browser"), "start_record", ("querytext",), ("IEEE_API_KEY",), (), "ieee_xplore", "restricted_browser", ("metadata_search", "api", "restricted_web_fallback"), "provider_subscription"),
    ("Google Scholar", "https://scholar.google.com/scholar", "search_google_scholar_adapter", "parse_google_scholar_item", ("public_browser", "enrichment"), "next_page", ("all_fields",), (), (), "public", "", ("metadata_search", "public_browser", "enrichment"), "free_or_provider_limited"),
    ("OpenAlex API", "https://api.openalex.org/works", "search_openalex", "parse_openalex_works", ("api",), "cursor", ("search",), (), ("OPENALEX_API_KEY", "CONTACT_EMAIL"), "api:openalex", "", ("metadata_search", "api"), "free_or_provider_limited"),
    ("Semantic Scholar API", "https://api.semanticscholar.org/graph/v1/paper/search", "search_semantic_scholar_api", "parse_semantic_scholar_api", ("api",), "token", ("title_abstract",), (), ("SEMANTIC_SCHOLAR_API_KEY",), "api:semantic_scholar", "", ("metadata_search", "api"), "free_or_provider_limited"),
    ("Crossref API", "https://api.crossref.org/works", "search_crossref", "parse_crossref_works", ("api",), "cursor", ("bibliographic",), (), ("CONTACT_EMAIL", "CROSSREF_MAILTO"), "api:crossref", "", ("metadata_search", "api"), "free_or_provider_limited"),
    ("arXiv API", "https://export.arxiv.org/api/query", "search_arxiv", "parse_arxiv_atom", ("api",), "start", ("all",), (), (), "public", "", ("metadata_search", "api", "preprint"), "free_or_provider_limited"),
    ("The Lens (lens.org)", "https://api.lens.org/scholarly/search", "search_lens_scholarly", "parse_lens_scholarly", ("api",), "scroll", ("title_abstract_full_text",), ("LENS_Scholarly_API_KEY",), (), "api:lens_scholarly", "", ("metadata_search", "api"), "provider_subscription"),
    ("Elsevier", "https://api.elsevier.com/content/search/sciencedirect", "search_elsevier_adapter", "parse_elsevier_sciencedirect_v2", ("api", "restricted_browser"), "start/count", ("title_abstract_keywords",), ("ELSEVIER_API_KEY",), ("ELSEVIER_INSTTOKEN",), "elsevier", "restricted_browser", ("metadata_search", "api", "restricted_web_fallback"), "provider_subscription"),
    ("SpringerLink", "https://api.springernature.com/meta/v2/json", "search_springerlink_adapter", "parse_springerlink", ("api", "restricted_browser"), "start/page", ("all_fields",), ("SPRINGER_API_KEY",), (), "springerlink", "restricted_browser", ("metadata_search", "api", "restricted_web_fallback"), "provider_subscription"),
    ("Nature", "https://www.nature.com/search", "search_nature_web_adapter", "parse_nature_search", ("public_browser", "restricted_browser"), "next_page", ("site_all_field",), (), (), "nature", "restricted_browser", ("metadata_search", "public_browser", "restricted_browser"), "provider_subscription"),
    ("ACS Publications", "https://pubs.acs.org/action/doSearch", "search_acs_web_adapter", "parse_acs_search", ("public_browser", "restricted_browser"), "next_page", ("site_all_field",), (), (), "acs_publications", "restricted_browser", ("metadata_search", "public_browser", "restricted_browser"), "provider_subscription"),
    ("RSC Publishing", "https://pubs.rsc.org/search-results", "search_rsc_web_adapter", "parse_rsc_search", ("public_browser", "restricted_browser"), "next_page", ("site_all_field",), (), (), "rsc_publishing", "restricted_browser", ("metadata_search", "public_browser", "restricted_browser"), "provider_subscription"),
    ("bioRxiv / medRxiv", "https://www.ebi.ac.uk/europepmc/webservices/rest/search", "search_biorxiv_adapter", "parse_biorxiv_europe_pmc", ("api",), "cursorMark", ("title_abstract",), (), (), "public", "", ("metadata_search", "api", "preprint", "actual_resolver:europe_pmc"), "free_or_provider_limited"),
    ("DOAJ (Directory of Open Access Journals)", "https://doaj.org/api/v4/search/articles", "search_doaj", "parse_doaj_articles", ("api",), "page", ("all_fields",), (), (), "public", "", ("metadata_search", "api", "open_access"), "free_or_provider_limited"),
    ("PMC (PubMed Central)", "https://eutils.ncbi.nlm.nih.gov/entrez/eutils/esearch.fcgi", "search_pmc_adapter", "parse_pmc_esummary", ("api",), "retstart", ("title_abstract",), (), ("NCBI_API_KEY", "PUBMED_API_KEY", "CONTACT_EMAIL", "NCBI_EMAIL", "NCBI_TOOL"), "api:ncbi", "", ("metadata_search", "api", "open_access"), "free_or_provider_limited"),
    ("PubMed", "https://eutils.ncbi.nlm.nih.gov/entrez/eutils/esearch.fcgi", "search_pubmed_adapter", "parse_pubmed_esummary", ("api",), "retstart", ("title_abstract",), (), ("NCBI_API_KEY", "PUBMED_API_KEY", "CONTACT_EMAIL", "NCBI_EMAIL", "NCBI_TOOL"), "api:ncbi", "PMC (PubMed Central)", ("metadata_search", "api"), "free_or_provider_limited"),
    ("Europe PMC", "https://www.ebi.ac.uk/europepmc/webservices/rest/search", "search_europe_pmc", "parse_europe_pmc", ("api",), "cursorMark", ("title_abstract",), (), (), "public", "", ("metadata_search", "api", "open_access"), "free_or_provider_limited"),
    ("Crossref Metadata Search (search.crossref.org)", "https://search.crossref.org", "search_crossref_metadata_web_adapter", "parse_crossref_metadata_web", ("public_browser",), "next_page", ("site_all_field",), (), (), "public", "", ("metadata_search", "public_browser"), "free_or_provider_limited"),
    ("DataCite Search (search.datacite.org)", "https://api.datacite.org/dois", "search_datacite", "parse_datacite_dois", ("api",), "page[number]", ("all_fields",), (), (), "public", "", ("metadata_search", "api"), "free_or_provider_limited"),
    ("ChemRxiv", "https://chemrxiv.org/engage/chemrxiv/public-api/v1/items", "search_chemrxiv_adapter", "parse_chemrxiv_items", ("api", "enrichment"), "offset", ("all_fields",), (), ("OPENALEX_API_KEY", "CONTACT_EMAIL"), "public", "OpenAlex API", ("metadata_search", "api", "enrichment", "preprint"), "free_or_provider_limited"),
    ("Semantic Scholar", "https://www.semanticscholar.org/search", "search_semantic_scholar_web_adapter", "parse_semantic_scholar_web", ("public_browser",), "next_page", ("site_all_field",), (), (), "public", "", ("metadata_search", "public_browser"), "free_or_provider_limited"),
    ("OpenReview", "https://api2.openreview.net/notes/search", "search_openreview", "parse_openreview_notes", ("api", "enrichment"), "offset", ("all_fields",), (), (), "public", "", ("metadata_search", "api", "enrichment"), "free_or_provider_limited"),
    ("IACR ePrint", "https://eprint.iacr.org/rss/rss.xml", "search_iacr_rss", "parse_iacr_eprint", ("api", "public_browser", "enrichment"), "archive/page", ("archive_title_abstract",), (), (), "public", "", ("metadata_search", "api", "public_browser", "preprint"), "free_or_provider_limited"),
    ("DBLP", "https://dblp.org/search/publ/api", "search_dblp", "parse_dblp_hits", ("api",), "offset", ("all_fields",), (), (), "public", "", ("metadata_search", "api"), "free_or_provider_limited"),
    ("ACM metadata", "https://dl.acm.org/action/doSearch", "search_acm_web_adapter", "parse_acm_search", ("public_browser", "restricted_browser"), "next_page", ("site_all_field",), (), (), "acm_metadata", "restricted_browser", ("metadata_search", "public_browser", "restricted_browser"), "provider_subscription"),
    ("USENIX", "https://www.usenix.org/search/site", "search_usenix_web_adapter", "parse_usenix_search", ("public_browser",), "next_page", ("site_all_field",), (), (), "public", "", ("metadata_search", "public_browser", "open_access"), "free_or_provider_limited"),
    ("CORE", "https://api.core.ac.uk/v3/search/works", "search_core", "parse_core_works", ("api",), "offset", ("all_fields",), (), ("CORE_API_KEY",), "api:core", "", ("metadata_search", "api", "open_access"), "free_or_provider_limited"),
    ("OpenAIRE", "https://api.openaire.eu/graph/v1/researchProducts", "search_openaire", "parse_openaire_products", ("api",), "page", ("all_fields",), (), ("OPENAIRE_API_KEY",), "api:openaire", "", ("metadata_search", "api", "open_access"), "free_or_provider_limited"),
    ("Springer", "https://api.springernature.com/meta/v2/json", "search_springer_alias_adapter", "parse_springer_alias", ("api", "restricted_browser"), "start/page", ("all_fields",), ("SPRINGER_API_KEY",), (), "springerlink", "restricted_browser", ("metadata_search", "api", "restricted_web_fallback"), "provider_subscription"),
    ("CNKI (中国知网)", "https://www.cnki.net/", "search_cnki_web_adapter", "parse_cnki_search", ("public_browser", "restricted_browser"), "next_page", ("verified_site_search_field",), (), (), "cnki", "restricted_browser", ("metadata_search", "public_browser", "restricted_browser"), "provider_subscription"),
    ("万方数据", "https://c.wanfangdata.com.cn/", "search_wanfang_web_adapter", "parse_wanfang_search", ("public_browser", "restricted_browser"), "resource_type/next_page", ("verified_site_search_field",), (), (), "wanfang_data", "restricted_browser", ("metadata_search", "public_browser", "restricted_browser"), "provider_subscription"),
)


_PATENT_SEARCH_ROWS = (
    ("Google Patents", "https://patents.google.com/", "search_google_patents_browser", "parse_google_patents_results", ("xhr", "public_browser"), "next_page", ("comprehensive",), (), (), "public", "", ("metadata_search", "xhr", "public_browser"), "free_or_provider_limited"),
    ("EPO Open Patent Services (OPS) API", "https://ops.epo.org/3.2/rest-services/published-data/search", "search_epo_ops", "parse_epo_ops_results", ("api",), "range", ("title", "abstract"), ("EPO_OPS_KEY", "EPO_OPS_SECRET"), (), "api:epo_ops", "", ("metadata_search", "api", "bibliographic"), "provider_subscription"),
    ("USPTO Open Data Portal", "https://api.uspto.gov/api/v1/patent/applications/search", "search_uspto_odp", "parse_uspto_odp_results", ("api",), "offset", ("title", "abstract", "claims"), ("USPTO_ODP_API_KEY",), (), "api:uspto_odp", "", ("metadata_search", "api"), "free_or_provider_limited"),
    ("WIPO PATENTSCOPE API", "https://patentscope.wipo.int/search/en/search.jsf", "search_wipo_adapter", "parse_wipo_patentscope_results", ("public_browser", "soap_probe"), "next_page", ("query_field_unverified",), (), ("PATENTSCOPE_WEBSERVICE_USERNAME", "PATENTSCOPE_WEBSERVICE_PASSWORD", "PATENTSCOPE_WSDL_URL"), "public", "", ("metadata_search", "public_browser", "optional_soap_probe", "query_field_unverified"), "free_or_provider_limited"),
    ("PQAI API (Patent Quality AI)", "https://api.projectpq.ai/search/102", "search_pqai", "parse_pqai_results", ("api",), "response_cursor", ("comprehensive",), ("PQAI_API_KEY",), (), "api:pqai", "", ("metadata_search", "api"), "free_or_provider_limited"),
    ("The Lens (lens.org)", "https://api.lens.org/patent/search", "search_lens_patent", "parse_lens_patent_results", ("api",), "scroll", ("title_claims_description",), ("LENS_Patents_API_KEY",), (), "api:lens_patents", "", ("metadata_search", "api"), "provider_subscription"),
    ("Google BigQuery", "bigquery://patents-public-data.patents.publications", "search_bigquery_adapter", "parse_bigquery_patent_rows", ("cost_api",), "stream", ("multilingual_title", "multilingual_abstract", "multilingual_claims"), ("GOOGLE_APPLICATION_CREDENTIALS",), (), "api:google_bigquery", "", ("metadata_search", "cost_api", "bibliographic"), "metered_approval_required"),
    ("CNKI (中国知网)", "https://kns.cnki.net/res/category/patent", "search_cnki_patent_adapter", "parse_cnki_patent_search", ("public_browser", "restricted_browser"), "next_page", ("verified_patent_search_field",), (), (), "cnki", "restricted_browser", ("metadata_search", "public_browser", "restricted_browser"), "provider_subscription"),
    ("万方数据", "https://c.wanfangdata.com.cn/patent", "search_wanfang_patent_adapter", "parse_wanfang_patent_search", ("public_browser", "restricted_browser"), "next_page", ("verified_patent_search_field",), (), (), "wanfang_data", "restricted_browser", ("metadata_search", "public_browser", "restricted_browser"), "provider_subscription"),
    ("度衍", "https://www.uyanip.com/", "search_uyanip_patent_adapter", "parse_uyanip_patent_search", ("public_browser", "restricted_browser"), "next_page", ("verified_patent_search_field",), (), ("uyanip_account", "uyanip_password"), "uyanip", "restricted_browser", ("metadata_search", "public_browser", "site_personal_auth"), "free_or_provider_limited"),
)


_SEARCH_NOMINAL_ENDPOINTS = {
    (
        "literature",
        "bioRxiv / medRxiv",
    ): "https://api.biorxiv.org/details",
}

_SEARCH_FALLBACK_AUTH_SCOPES = {
    ("literature", "ChemRxiv"): "api:openalex",
}


def _search_specs(record_type: RecordType, rows: tuple[tuple[object, ...], ...]) -> tuple[SearchAdapterSpec, ...]:
    result: list[SearchAdapterSpec] = []
    for order, row in enumerate(rows, 1):
        (
            name, endpoint, runner, parser, paths, pagination, query_fields,
            required, optional, auth_scope, fallback, capabilities, cost,
        ) = row
        result.append(
            SearchAdapterSpec(
                adapter_id=f"search.{record_type}.{_slug(str(name))}",
                provider_id=_provider_id(str(name)),
                order=order,
                display_name=str(name),
                record_type=record_type,
                endpoint=str(endpoint),
                actual_adapter=str(runner),
                parser=str(parser),
                paths=tuple(paths),
                pagination=str(pagination),
                query_fields=tuple(query_fields),
                auth_scope=str(auth_scope),
                config_keys=tuple(required),
                optional_config_keys=tuple(optional),
                fallback_resolver=str(fallback),
                capabilities=tuple(capabilities),
                cost=str(cost),
                nominal_endpoint=_SEARCH_NOMINAL_ENDPOINTS.get(
                    (record_type, str(name)),
                    str(endpoint),
                ),
                fallback_auth_scope=_SEARCH_FALLBACK_AUTH_SCOPES.get(
                    (record_type, str(name)),
                    "",
                ),
            )
        )
    return tuple(result)


LITERATURE_SEARCH_ADAPTERS = _search_specs("literature", _LITERATURE_SEARCH_ROWS)
PATENT_SEARCH_ADAPTERS = _search_specs("patent", _PATENT_SEARCH_ROWS)


_ENDPOINT_BY_RECORD_AND_NAME = {
    **{
        ("literature", row[0]): _SEARCH_NOMINAL_ENDPOINTS.get(
            ("literature", str(row[0])),
            row[1],
        )
        for row in _LITERATURE_SEARCH_ROWS
    },
    **{
        ("patent", row[0]): _SEARCH_NOMINAL_ENDPOINTS.get(
            ("patent", str(row[0])),
            row[1],
        )
        for row in _PATENT_SEARCH_ROWS
    },
}
_SYNTHETIC_DOWNLOAD_ENDPOINTS = {
    "Sci-Hub": "https://www.scihub.net.cn/sci-hub/{doi}",
    "doi_resolver": "https://doi.org/{doi}",
    "input_url": "{url}",
    "Annual Reviews": "https://www.annualreviews.org/doi/pdf/{doi}",
    # These nominal providers supplied search metadata only.  Their current
    # download adapter does not invoke the provider API; it consumes an
    # observed locator and otherwise resolves through Google Patents.
    "USPTO Open Data Portal": "metadata-origin://uspto-odp",
    "PQAI API (Patent Quality AI)": "metadata-origin://pqai",
    "EPO Open Patent Services (OPS) API": "metadata-origin://epo-ops",
    "Google BigQuery": "metadata-origin://google-bigquery",
}


# The literature order is deliberately the historic 33 priority entries plus
# CNKI and Wanfang.  Do not sort this table.
_LITERATURE_DOWNLOAD_ROWS = (
    ("Sci-Hub", "parse_literature_scihub", ("identifier:doi",), "public", (), (), "", ("doi_form", "open_direct_pdf", "robot_challenge_possible"), "free_or_provider_limited", True),
    ("arXiv API", "parse_literature_api_pdf", ("identifier:arxiv_id", "identifier:doi", "locator:landing"), "public", (), (), "", ("open_api", "direct_pdf"), "free_or_provider_limited", True),
    ("bioRxiv / medRxiv", "parse_literature_api_pdf", ("identifier:doi", "locator:landing"), "public", (), (), "Europe PMC", ("open_preprint", "doi_pdf_pattern", "landing_page_discovery"), "free_or_provider_limited", True),
    ("IACR ePrint", "parse_literature_api_pdf", ("identifier:raw_id", "locator:landing"), "public", (), (), "", ("open_preprint", "direct_pdf_pattern"), "free_or_provider_limited", True),
    ("The Lens (lens.org)", "parse_literature_api_pdf", ("identifier:doi", "locator:landing"), "api:lens_scholarly", ("LENS_Scholarly_API_KEY",), (), "", ("required_api_key", "metadata_api", "open_access_url_discovery"), "provider_subscription", True),
    ("Web of Science Starter API (Clarivate)", "parse_literature_api_pdf", ("identifier:doi", "locator:landing"), "web_of_science", ("CLARIVATE_API_KEY",), (), "restricted_browser", ("required_api_key", "metadata_api", "restricted_web_fallback"), "provider_subscription", True),
    ("doi_resolver", "parse_literature_doi_resolver", ("identifier:doi",), "public", (), (), "", ("doi_landing_page", "no_browser_fallback"), "free_or_provider_limited", True),
    ("Crossref API", "parse_literature_api_pdf", ("identifier:doi",), "api:crossref", (), ("CONTACT_EMAIL", "CROSSREF_MAILTO"), "", ("open_api", "metadata_pdf_link"), "free_or_provider_limited", True),
    ("OpenAlex API", "parse_literature_api_pdf", ("identifier:doi",), "api:openalex", (), ("OPENALEX_API_KEY", "CONTACT_EMAIL"), "", ("open_api", "open_access_pdf"), "free_or_provider_limited", True),
    ("Semantic Scholar API", "parse_literature_api_pdf", ("identifier:doi",), "api:semantic_scholar", (), ("SEMANTIC_SCHOLAR_API_KEY",), "", ("open_api", "optional_api_key", "open_access_pdf"), "free_or_provider_limited", True),
    ("Europe PMC", "parse_literature_api_pdf", ("identifier:doi", "identifier:pmcid"), "public", (), (), "", ("open_api", "full_text_url"), "free_or_provider_limited", True),
    ("PMC (PubMed Central)", "parse_literature_api_pdf", ("identifier:pmcid", "identifier:doi"), "api:ncbi", (), ("NCBI_API_KEY", "PUBMED_API_KEY"), "", ("open_repository", "direct_pdf"), "free_or_provider_limited", True),
    ("PubMed", "parse_literature_api_pdf", ("identifier:pmid", "identifier:doi"), "api:ncbi", (), ("NCBI_API_KEY", "PUBMED_API_KEY"), "Europe PMC -> PMC (PubMed Central)", ("open_api", "europe_pmc_discovery", "pmc_fallback"), "free_or_provider_limited", True),
    ("DOAJ (Directory of Open Access Journals)", "parse_literature_api_pdf", ("identifier:doi", "locator:landing"), "public", (), (), "", ("open_api", "landing_page_discovery"), "free_or_provider_limited", True),
    ("DataCite Search (search.datacite.org)", "parse_literature_api_pdf", ("identifier:doi", "locator:landing"), "public", (), (), "", ("open_api", "repository_url_discovery", "zenodo_file_api", "figshare_file_api"), "free_or_provider_limited", True),
    ("OpenReview", "parse_literature_api_pdf", ("identifier:raw_id", "locator:landing"), "public", (), (), "", ("open_platform", "direct_pdf_pattern"), "free_or_provider_limited", True),
    ("DBLP", "parse_literature_api_pdf", ("identifier:doi", "identifier:raw_id", "locator:landing"), "public", (), (), "", ("open_metadata", "arxiv_pdf_discovery", "landing_page_discovery"), "free_or_provider_limited", True),
    ("CORE", "parse_literature_api_pdf", ("identifier:doi", "identifier:raw_id"), "api:core", (), ("CORE_API_KEY",), "", ("open_api", "optional_api_key", "download_url"), "free_or_provider_limited", True),
    ("OpenAIRE", "parse_literature_api_pdf", ("identifier:doi", "identifier:raw_id"), "api:openaire", (), ("OPENAIRE_API_KEY",), "", ("open_api", "optional_api_key", "access_url"), "free_or_provider_limited", True),
    ("ChemRxiv", "parse_literature_api_pdf", ("identifier:doi", "locator:landing"), "api:openalex", (), ("OPENALEX_API_KEY", "CONTACT_EMAIL"), "OpenAlex API", ("openalex_fallback", "landing_page_discovery"), "free_or_provider_limited", True),
    ("Google Scholar", "parse_literature_template_or_search", ("identifier:doi", "locator:landing", "metadata:title"), "public", (), (), "", ("public_browser", "landing_page_discovery"), "free_or_provider_limited", True),
    ("Crossref Metadata Search (search.crossref.org)", "parse_literature_api_pdf", ("identifier:doi",), "api:crossref", (), ("CONTACT_EMAIL", "CROSSREF_MAILTO"), "OpenAlex API -> Crossref API", ("metadata_only", "openalex_fallback", "crossref_api_fallback"), "free_or_provider_limited", True),
    ("Semantic Scholar", "parse_literature_api_pdf", ("identifier:doi",), "api:semantic_scholar", (), ("SEMANTIC_SCHOLAR_API_KEY",), "OpenAlex API -> Semantic Scholar API", ("metadata_only", "openalex_fallback", "api_preferred"), "free_or_provider_limited", True),
    ("USENIX", "parse_literature_usenix", ("locator:landing", "metadata:title"), "public", (), (), "", ("open_platform", "system_files_pdf", "landing_page_discovery"), "free_or_provider_limited", True),
    ("Elsevier", "parse_literature_api_pdf", ("identifier:doi", "locator:landing"), "elsevier", ("ELSEVIER_API_KEY",), ("ELSEVIER_INSTTOKEN",), "restricted_browser", ("required_api_key", "publisher_pdf_api", "sciencedirect_auth_path", "institution_or_carsi_auth_path", "restricted_web_fallback"), "provider_subscription", True),
    ("SpringerLink", "parse_literature_api_pdf", ("identifier:doi", "locator:landing"), "springerlink", ("SPRINGER_API_KEY",), (), "restricted_browser", ("required_api_key", "publisher_metadata_api", "direct_pdf_pattern", "restricted_web_fallback"), "provider_subscription", True),
    ("Springer", "parse_literature_api_pdf", ("identifier:doi", "locator:landing"), "springerlink", ("SPRINGER_API_KEY",), (), "restricted_browser", ("required_api_key", "publisher_metadata_api", "direct_pdf_pattern", "restricted_web_fallback"), "provider_subscription", True),
    ("IEEE Xplore API", "parse_literature_api_pdf", ("identifier:doi", "locator:landing"), "ieee_xplore", ("IEEE_API_KEY",), (), "restricted_browser", ("required_api_key", "metadata_api", "restricted_web_fallback"), "provider_subscription", True),
    ("Nature", "parse_literature_api_pdf", ("identifier:doi", "locator:landing"), "nature", (), (), "restricted_browser", ("restricted_web", "direct_pdf_pattern"), "provider_subscription", True),
    ("ACS Publications", "parse_literature_api_pdf", ("identifier:doi", "locator:landing"), "acs_publications", (), (), "restricted_browser", ("restricted_web", "direct_pdf_pattern"), "provider_subscription", True),
    ("RSC Publishing", "parse_literature_template_or_search", ("identifier:doi", "locator:landing"), "rsc_publishing", (), (), "restricted_browser", ("restricted_web", "landing_page_discovery"), "provider_subscription", True),
    ("ACM metadata", "parse_literature_api_pdf", ("identifier:doi", "locator:landing"), "acm_metadata", (), (), "restricted_browser", ("restricted_web", "direct_pdf_pattern"), "provider_subscription", True),
    ("Annual Reviews", "parse_literature_api_pdf", ("identifier:doi",), "annual_reviews", (), (), "restricted_browser", ("restricted_web", "direct_pdf_pattern"), "provider_subscription", True),
    ("CNKI (中国知网)", "parse_literature_cnki_observed", ("locator:landing", "locator:direct_pdf", "metadata:title"), "cnki", (), (), "", ("public_browser", "restricted_web", "observed_detail_url", "observed_pdf_action"), "provider_subscription", True),
    ("万方数据", "parse_literature_wanfang_observed", ("locator:landing", "locator:direct_pdf", "metadata:title"), "wanfang_data", (), (), "", ("public_browser", "restricted_web", "observed_detail_url", "observed_pdf_action"), "provider_subscription", True),
)


_PATENT_DOWNLOAD_ROWS = (
    ("Google Patents", "parse_patent_google_patents", ("identifier:publication_number",), "public", (), (), "", ("public_web", "landing_page_discovery", "direct_download_query"), "free_or_provider_limited", True),
    ("The Lens (lens.org)", "parse_patent_lens", ("identifier:publication_number", "locator:landing"), "api:lens_patents", ("LENS_Patents_API_KEY",), (), "conditional:Google Patents(new_identifier)", ("required_api_key", "metadata_api", "native_locator", "new_identifier_google_resolution"), "provider_subscription", True),
    ("input_url", "parse_patent_input_url", ("locator:landing", "locator:direct_pdf"), "unknown", (), (), "", ("metadata_field", "landing_page_discovery"), "free_or_provider_limited", True),
    ("USPTO Open Data Portal", "parse_patent_metadata_origin", ("identifier:publication_number", "locator:landing"), "public", (), (), "", ("metadata_origin", "source_owned_locator", "native_locator_if_observed"), "free_or_provider_limited", True),
    ("PQAI API (Patent Quality AI)", "parse_patent_metadata_origin", ("identifier:publication_number", "locator:landing"), "public", (), (), "", ("metadata_origin", "source_owned_locator", "native_locator_if_observed"), "free_or_provider_limited", True),
    ("EPO Open Patent Services (OPS) API", "parse_patent_metadata_origin", ("identifier:publication_number", "locator:landing"), "public", (), (), "", ("metadata_origin", "source_owned_locator", "native_locator_if_observed"), "free_or_provider_limited", True),
    ("WIPO PATENTSCOPE API", "parse_patent_template_or_search", ("identifier:publication_number", "locator:landing", "metadata:title"), "public", (), ("PATENTSCOPE_WEBSERVICE_USERNAME", "PATENTSCOPE_WEBSERVICE_PASSWORD", "PATENTSCOPE_WSDL_URL"), "", ("required_credentials", "public_web", "landing_page_discovery"), "free_or_provider_limited", True),
    ("Google BigQuery", "parse_patent_metadata_origin", ("identifier:publication_number", "locator:landing"), "public", (), (), "", ("metadata_origin", "source_owned_locator", "native_locator_if_observed"), "free_or_provider_limited", True),
    ("CNKI (中国知网)", "parse_patent_cnki_observed", ("identifier:publication_number", "locator:landing", "locator:direct_pdf"), "cnki", (), (), "", ("public_browser", "restricted_web", "observed_detail_url", "observed_pdf_action"), "provider_subscription", True),
    ("万方数据", "parse_patent_wanfang_observed", ("identifier:publication_number", "locator:landing", "locator:direct_pdf"), "wanfang_data", (), (), "", ("public_browser", "restricted_web", "observed_detail_url", "observed_pdf_action"), "provider_subscription", True),
    ("度衍", "parse_patent_uyanip_observed", ("identifier:publication_number", "locator:landing", "locator:direct_pdf"), "uyanip", (), ("uyanip_account", "uyanip_password"), "", ("public_browser", "site_personal_auth", "observed_detail_url", "observed_pdf_action"), "free_or_provider_limited", True),
)


def _download_specs(record_type: RecordType, rows: tuple[tuple[object, ...], ...]) -> tuple[DownloadAdapterSpec, ...]:
    result: list[DownloadAdapterSpec] = []
    for order, row in enumerate(rows, 1):
        name, adapter, required, auth_scope, config, optional, fallback, capabilities, cost, enabled = row
        result.append(
            DownloadAdapterSpec(
                adapter_id=f"download.{record_type}.{_slug(str(name))}",
                provider_id=_provider_id(str(name)),
                order=order,
                display_name=str(name),
                record_type=record_type,
                endpoint=str(
                    _SYNTHETIC_DOWNLOAD_ENDPOINTS.get(
                        str(name),
                        _ENDPOINT_BY_RECORD_AND_NAME.get((record_type, name), "unknown"),
                    )
                ),
                actual_adapter=str(adapter),
                required_locators=tuple(required),
                auth_scope=str(auth_scope),
                config_keys=tuple(config),
                optional_config_keys=tuple(optional),
                fallback_resolver=str(fallback),
                capabilities=tuple(capabilities),
                cost=str(cost),
                default_enabled=bool(enabled),
            )
        )
    return tuple(result)


LITERATURE_DOWNLOAD_ADAPTERS = _download_specs("literature", _LITERATURE_DOWNLOAD_ROWS)
PATENT_DOWNLOAD_ADAPTERS = _download_specs("patent", _PATENT_DOWNLOAD_ROWS)

LITERATURE_SEARCH_CHANNEL_ORDER = tuple(spec.display_name for spec in LITERATURE_SEARCH_ADAPTERS)
PATENT_SEARCH_CHANNEL_ORDER = tuple(spec.display_name for spec in PATENT_SEARCH_ADAPTERS)
LITERATURE_DOWNLOAD_CHANNEL_ORDER = tuple(spec.display_name for spec in LITERATURE_DOWNLOAD_ADAPTERS)
PATENT_DOWNLOAD_CHANNEL_ORDER = tuple(spec.display_name for spec in PATENT_DOWNLOAD_ADAPTERS)

# Short aliases make adoption in the two existing scripts straightforward.
LITERATURE_SEARCH_SPECS = LITERATURE_SEARCH_ADAPTERS
PATENT_SEARCH_SPECS = PATENT_SEARCH_ADAPTERS
LITERATURE_DOWNLOAD_SPECS = LITERATURE_DOWNLOAD_ADAPTERS
PATENT_DOWNLOAD_SPECS = PATENT_DOWNLOAD_ADAPTERS


def _build_providers() -> tuple[Provider, ...]:
    endpoints: dict[str, str] = {}
    capabilities: dict[str, set[str]] = {}
    names: dict[str, str] = {}
    all_specs = (
        *LITERATURE_SEARCH_ADAPTERS,
        *PATENT_SEARCH_ADAPTERS,
        *LITERATURE_DOWNLOAD_ADAPTERS,
        *PATENT_DOWNLOAD_ADAPTERS,
    )
    for spec in all_specs:
        names.setdefault(spec.provider_id, spec.display_name)
        endpoint = (
            spec.nominal_endpoint
            if isinstance(spec, SearchAdapterSpec) and spec.nominal_endpoint
            else spec.endpoint
        )
        if endpoint.startswith(("http://", "https://")):
            match = re.match(r"https?://[^/]+", endpoint)
            endpoints.setdefault(spec.provider_id, match.group(0) if match else endpoint)
        else:
            endpoints.setdefault(spec.provider_id, endpoint)
        capabilities.setdefault(spec.provider_id, set()).update(spec.capabilities)
    return tuple(
        Provider(provider_id, names[provider_id], endpoints[provider_id], tuple(sorted(capabilities[provider_id])))
        for provider_id in names
    )


PROVIDERS = _build_providers()
PROVIDER_BY_ID = {provider.provider_id: provider for provider in PROVIDERS}


def get_provider(provider_id: str) -> Provider:
    return PROVIDER_BY_ID[provider_id]


def get_search_adapters(record_type: RecordType | None = None) -> tuple[SearchAdapterSpec, ...]:
    if record_type == "literature":
        return LITERATURE_SEARCH_ADAPTERS
    if record_type == "patent":
        return PATENT_SEARCH_ADAPTERS
    if record_type is None:
        return (*LITERATURE_SEARCH_ADAPTERS, *PATENT_SEARCH_ADAPTERS)
    raise ValueError(f"Unsupported record_type: {record_type!r}")


def get_download_adapters(
    record_type: RecordType | None = None,
    *,
    include_disabled: bool = True,
) -> tuple[DownloadAdapterSpec, ...]:
    if record_type == "literature":
        specs = LITERATURE_DOWNLOAD_ADAPTERS
    elif record_type == "patent":
        specs = PATENT_DOWNLOAD_ADAPTERS
    elif record_type is None:
        specs = (*LITERATURE_DOWNLOAD_ADAPTERS, *PATENT_DOWNLOAD_ADAPTERS)
    else:
        raise ValueError(f"Unsupported record_type: {record_type!r}")
    return specs if include_disabled else tuple(spec for spec in specs if spec.default_enabled)


def search_adapter_names(record_type: RecordType) -> tuple[str, ...]:
    return tuple(spec.display_name for spec in get_search_adapters(record_type))


def download_adapter_names(record_type: RecordType, *, include_disabled: bool = True) -> tuple[str, ...]:
    return tuple(
        spec.display_name
        for spec in get_download_adapters(record_type, include_disabled=include_disabled)
    )


def locator_requirements_satisfied(
    spec: SearchAdapterSpec | DownloadAdapterSpec,
    available_locators: tuple[str, ...] | list[str] | set[str] | frozenset[str],
) -> bool:
    available = {str(item).strip().casefold() for item in available_locators}
    required = {item.casefold() for item in spec.required_locators}
    if not required:
        return True
    if spec.required_locator_mode == "all":
        return required.issubset(available)
    return bool(required.intersection(available))


def registry_snapshot() -> dict[str, object]:
    return {
        "schema_version": REGISTRY_SCHEMA_VERSION,
        "registry_version": REGISTRY_VERSION,
        "providers": [asdict(item) for item in PROVIDERS],
        "search": {
            "literature": [asdict(item) for item in LITERATURE_SEARCH_ADAPTERS],
            "patent": [asdict(item) for item in PATENT_SEARCH_ADAPTERS],
        },
        "download": {
            "literature": [asdict(item) for item in LITERATURE_DOWNLOAD_ADAPTERS],
            "patent": [asdict(item) for item in PATENT_DOWNLOAD_ADAPTERS],
        },
    }


def validate_registry() -> None:
    expected = {
        ("search", "literature"): 32,
        ("search", "patent"): 10,
        ("download", "literature"): 35,
        ("download", "patent"): 11,
    }
    groups = {
        ("search", "literature"): LITERATURE_SEARCH_ADAPTERS,
        ("search", "patent"): PATENT_SEARCH_ADAPTERS,
        ("download", "literature"): LITERATURE_DOWNLOAD_ADAPTERS,
        ("download", "patent"): PATENT_DOWNLOAD_ADAPTERS,
    }
    for key, specs in groups.items():
        if len(specs) != expected[key]:
            raise RuntimeError(f"Registry count drift for {key}: {len(specs)} != {expected[key]}")
        if tuple(spec.order for spec in specs) != tuple(range(1, len(specs) + 1)):
            raise RuntimeError(f"Registry order is not contiguous for {key}")
        names = tuple(spec.display_name for spec in specs)
        if len(names) != len(set(names)):
            raise RuntimeError(f"Duplicate channel display name within {key}")
        if any(spec.provider_id not in PROVIDER_BY_ID for spec in specs):
            raise RuntimeError(f"Unknown provider in {key}")
    scihub = LITERATURE_DOWNLOAD_ADAPTERS[0]
    if scihub.display_name != "Sci-Hub" or not scihub.default_enabled:
        raise RuntimeError("Sci-Hub must remain first and default enabled")


validate_registry()


__all__ = [
    "REGISTRY_SCHEMA_VERSION",
    "REGISTRY_VERSION",
    "Provider",
    "SearchAdapterSpec",
    "DownloadAdapterSpec",
    "PROVIDERS",
    "PROVIDER_BY_ID",
    "LITERATURE_SEARCH_ADAPTERS",
    "PATENT_SEARCH_ADAPTERS",
    "LITERATURE_DOWNLOAD_ADAPTERS",
    "PATENT_DOWNLOAD_ADAPTERS",
    "LITERATURE_SEARCH_CHANNEL_ORDER",
    "PATENT_SEARCH_CHANNEL_ORDER",
    "LITERATURE_DOWNLOAD_CHANNEL_ORDER",
    "PATENT_DOWNLOAD_CHANNEL_ORDER",
    "LITERATURE_SEARCH_SPECS",
    "PATENT_SEARCH_SPECS",
    "LITERATURE_DOWNLOAD_SPECS",
    "PATENT_DOWNLOAD_SPECS",
    "get_provider",
    "get_search_adapters",
    "get_download_adapters",
    "search_adapter_names",
    "download_adapter_names",
    "locator_requirements_satisfied",
    "registry_snapshot",
    "validate_registry",
]
