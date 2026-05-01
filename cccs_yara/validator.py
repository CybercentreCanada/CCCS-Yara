import re
import uuid
from datetime import datetime
from typing import Annotated

import baseconv
from plyara.utils import generate_hash
from pydantic import (
    BaseModel,
    BeforeValidator,
    ConfigDict,
    Field,
    StringConstraints,
    ValidationInfo,
    field_validator,
    model_validator,
)

from cccs_yara.constants import (
    ACTOR_TYPE_KEYWORDS,
    BASE62_REGEX,
    CATEGORY_KEYWORDS,
    DATE_FORMATS,
    GENERIC_HASH_REGEX,
    MALWARE_TYPE_KEYWORDS,
    SHA256_REGEX,
)


def transform_version(version_str: str) -> str:
    if not version_str:
        # If the version string is empty, return the default version
        return "1.0"
    elif isinstance(version_str, int):
        # If the version is an integer, convert it to a string with .0
        return f"{version_str}.0"

    version_str = str(version_str).strip()

    # Keep valid dotted versions unchanged.
    if re.fullmatch(r"\d+\.\d+", version_str):
        return version_str

    if version_str.startswith("."):
        version_str = "0" + version_str
    elif version_str.endswith("."):
        version_str = version_str + "0"
    elif version_str.isdigit():
        version_str = version_str + ".0"
    else:
        version_str = "1.0"

    return version_str


def transform_date(date_str: str) -> str:
    if not date_str:
        # If the date string is empty, return the current date
        return datetime.now(tz=datetime.timezone.utc).strftime("%Y-%m-%d")
    for date_format in DATE_FORMATS:
        try:
            # Convert the date string to a standardized format
            parsed_date = datetime.strptime(date_str, date_format).replace(tzinfo=datetime.timezone.utc)
            return parsed_date.strftime("%Y-%m-%d")
        except Exception:  # noqa: BLE001, S112
            continue

    raise ValueError(f"Date '{date_str}' is not in a recognized format.")


#  CCCS YARA Standard Configuration represented as a Pydantic model
class RuleValidatorModel(BaseModel, extra="allow"):
    model_config = ConfigDict(validate_by_alias=True, validate_by_name=True)

    @model_validator(mode="before")
    def before_validation(cls, data: dict, info: ValidationInfo) -> dict:
        for key, value in cls.model_json_schema().get("properties", {}).items():
            # Ignore fields that would have just a single value assigned
            if "type" in value:
                continue

            if value["anyOf"][0]["type"] == "array" and key in data:
                # Ensure set fields are converted to sets
                if isinstance(data[key], set):
                    pass
                elif isinstance(data[key], list):
                    data[key] = set(data[key])
                else:
                    data[key] = {[data[key]]}

        # Preserve all original metadata fields using keys with "original_"
        for key, value in list(data.items()):
            if key.startswith("original_"):
                continue
            elif f"original_{key}" not in data:
                # Don't overwrite if already preserved
                data[f"original_{key}"] = value

        # Auto-generate fingerprint if missing
        if not data.get("fingerprint"):
            data["fingerprint"] = generate_hash(info.context["rule"], legacy=True)
        elif data["fingerprint"].startswith("v1_sha256_"):
            # Newer version of generating the fingerprint, strip the prefix
            data["fingerprint"] = data["fingerprint"][10:]

        # Auto-generate id if missing
        if not data.get("id") or not BASE62_REGEX.match(data["id"]):
            data["id"] = str(baseconv.base62.encode(uuid.uuid4().int))

        # Apply field aliases if provided
        if info.context.get("aliases"):
            for target_field, alias_pattern in info.context["aliases"].items():
                for key in list(data.keys()):
                    if alias_pattern.match(key):
                        if target_field not in data:
                            # A single value is assigned to the field
                            data[target_field] = data.pop(key)
                        else:
                            # If the target field already exists, we need to merge values
                            if not isinstance(data[target_field], set):
                                if isinstance(data[target_field], list):
                                    data[target_field] = set(data[target_field])
                                else:
                                    data[target_field] = {data[target_field]}

                            if isinstance(data[key], (set, list)):
                                data[target_field].update(data.pop(key))
                            else:
                                data[target_field].add(data.pop(key))

        # Apply default metadata if provided
        default_metadata = info.context.get("default_metadata", {})
        for key, value in default_metadata.items():
            if key not in data or not data[key]:
                data[key] = value

        # Insert a description based on the derived metadata if missing
        if "description" not in data or not data["description"]:
            description = "Detects "
            if data.get("malware"):
                description += f"{', '.join(data['malware'])} samples "
            else:
                description += "samples "
            if data.get("actor"):
                description += f"used by {', '.join(data['actor'])}."

            data["description"] = description

        return data

    id: Annotated[str, StringConstraints(pattern=BASE62_REGEX)] = Field(
        description="Autogenerated unique identifier based on RFC 4122 if a uuid is not already present",
    )

    fingerprint: Annotated[str, StringConstraints(pattern=SHA256_REGEX)] = Field(
        description="Autogenerated based on SHA256 hash of string values and the condition statement of the YARA rule",
    )

    version: Annotated[str, BeforeValidator(transform_version), StringConstraints(pattern=r"^\d+\.\d+$")] = Field(
        default="1.0",
        description="Revision of the rule, autogenerated as 1.0 if no present",
    )

    score: int | None = Field(
        default=None,
        description="Score assigned to the rule based on its reliability and effectiveness",
    )

    minimum_yara: Annotated[str, StringConstraints(pattern=r"^\d+\.\d+$")] | None = Field(
        default=None,
        description="Minimum YARA version required to properly evaluate the rule",
    )

    date: Annotated[str, BeforeValidator(transform_date), StringConstraints(pattern=r"^\d{4}-\d{2}-\d{2}$")] | None = (
        Field(
            default=None,
            description="Date stamp of when the rule was created",
            alias="creation_date",
        )
    )

    modified: Annotated[
        str,
        BeforeValidator(transform_date),
        StringConstraints(pattern=r"^\d{4}-\d{2}-\d{2}$"),
    ] = Field(
        default=None,
        description="Date stamp of when the rule was last modified",
        alias="last_modified",
    )

    tags: Annotated[set[str], BeforeValidator(lambda x: [x] if isinstance(x, str) else x)] | None = Field(
        default=None,
        description="List of tags associated with the rule for categorization and searchability",
    )

    status: Annotated[str, StringConstraints(pattern=r"^(TESTING|RELEASED|DEPRECATED)$")] = Field(
        default="RELEASED",
        description="Status of the rule indicating its reliability and maintenance state",
    )

    sharing: Annotated[
        str,
        BeforeValidator(lambda x: "TLP:CLEAR" if x == "TLP:WHITE" else x),
        StringConstraints(pattern=r"^TLP:(CLEAR|GREEN|AMBER\+STRICT|AMBER)(\/\/COMMERCIAL)?$"),
    ] = Field(
        description="Sharing level of the rule indicating its accessibility.",
        alias="classification",
    )

    source: Annotated[str, StringConstraints(to_upper=True)] = Field(
        description="Origin or provider of the rule for attribution and reference",
    )

    author: str = Field(
        description="Name or identifier of the individual or organization that authored the rule",
    )

    description: str = Field(
        description="Detailed explanation of the rule's purpose, functionality, and detection capabilities",
    )

    category: Annotated[str, StringConstraints(pattern=f"^({'|'.join(CATEGORY_KEYWORDS.keys())})$")] = Field(
        description="Classification of the rule based on the type of threat or behavior it detects",
    )

    info: (
        Annotated[set[str], BeforeValidator(lambda x: [x.upper()] if isinstance(x, str) else [i.upper() for i in x])]
        | None
    ) = Field(
        default=None,
        description="Additional information or context about the rule to aid understanding and usage",
    )

    @field_validator("info")
    def validate_info(cls, v, info: ValidationInfo):
        if info.data.get("category") != "INFO":
            raise ValueError("The 'info' field can only be set if the category is 'INFO'.")
        return v

    exploit: (
        Annotated[set[str], BeforeValidator(lambda x: [x.upper()] if isinstance(x, str) else [i.upper() for i in x])]
        | None
    ) = Field(
        default=None,
        description="Specific exploit or vulnerability that the rule is designed to detect",
    )

    @field_validator("exploit")
    def validate_exploit(cls, v, info: ValidationInfo):
        if info.data.get("category") != "EXPLOIT":
            raise ValueError("The 'exploit' field can only be set if the category is 'EXPLOIT'.")
        return v

    technique: (
        Annotated[set[str], BeforeValidator(lambda x: [x.upper()] if isinstance(x, str) else [i.upper() for i in x])]
        | None
    ) = Field(
        default=None,
        description="Specific technique or tactic that the rule is designed to detect",
    )

    @field_validator("technique")
    def validate_technique(cls, v, info: ValidationInfo):
        if info.data.get("category") != "TECHNIQUE":
            raise ValueError("The 'technique' field can only be set if the category is 'TECHNIQUE'.")
        return v

    tool: (
        Annotated[set[str], BeforeValidator(lambda x: [x.upper()] if isinstance(x, str) else [i.upper() for i in x])]
        | None
    ) = Field(
        default=None,
        description="Specific tool or software that the rule is designed to detect",
    )

    @field_validator("tool")
    def validate_tool(cls, v, info: ValidationInfo):
        if info.data.get("category") != "TOOL":
            raise ValueError("The 'tool' field can only be set if the category is 'TOOL'.")
        return v

    malware: (
        Annotated[set[str], BeforeValidator(lambda x: [x.upper()] if isinstance(x, str) else [i.upper() for i in x])]
        | None
    ) = Field(
        default=None,
        description="Specific malware family or variant that the rule is designed to detect",
    )

    @field_validator("malware")
    def validate_malware(cls, v, info: ValidationInfo):
        if info.data.get("category") != "MALWARE":
            raise ValueError("The 'malware' field can only be set if the category is 'MALWARE'.")
        return v

    malware_type: (
        Annotated[
            set[Annotated[str, StringConstraints(pattern=r"^(" + "|".join(MALWARE_TYPE_KEYWORDS.keys()) + ")$")]],
            BeforeValidator(
                lambda x: (
                    [x.upper()]
                    if isinstance(x, str) and x.upper() in MALWARE_TYPE_KEYWORDS
                    else [i.upper() for i in x if i.upper() in MALWARE_TYPE_KEYWORDS]
                )
            ),
        ]
        | None
    ) = Field(
        default=None,
        description="Type of malware associated with the rule",
    )

    mitre_att: (
        Annotated[
            set[Annotated[str, StringConstraints(pattern=r"^(TA|T|M|G|S)[0-9]{4}(\.[0-9]{3})?$")]],
            BeforeValidator(
                lambda x: (
                    [x.upper()]
                    if isinstance(x, str) and x.upper().startswith(("TA", "T", "M", "G", "S"))
                    else [i.upper() for i in x if i.upper().startswith(("TA", "T", "M", "G", "S"))]
                )
            ),
        ]
        | None
    ) = Field(
        default=None,
        description="List of MITRE ATT&CK techniques associated with the rule for mapping and correlation",
    )

    actor_type: (
        Annotated[
            set[str],
            BeforeValidator(
                lambda x: (
                    [x.upper()]
                    if isinstance(x, str) and x.upper() in ACTOR_TYPE_KEYWORDS
                    else [i.upper() for i in x if i.upper() in ACTOR_TYPE_KEYWORDS]
                )
            ),
        ]
        | None
    ) = Field(
        default=None,
        description="Type of threat actor associated with the rule",
        max_length=2,
    )

    actor: (
        Annotated[
            str,
            BeforeValidator(lambda x: x.upper() if isinstance(x, str) else x.pop()),
            StringConstraints(to_upper=True),
        ]
        | None
    ) = Field(
        default=None,
        description="Name or identifier of the threat actor associated with the rule",
    )

    # @field_validator("actor")
    # def validate_actor(cls, v, info: ValidationInfo):
    #     if not info.data["actor_type"]:
    #         raise ValueError("The 'actor' field can only be set if the 'actor_type' is specified.")
    #     return v

    mitre_group: (
        Annotated[
            str,
            BeforeValidator(lambda x: x if isinstance(x, str) else next(set(x))),
            StringConstraints(to_upper=True),
        ]
        | None
    ) = Field(
        default=None,
        description="MITRE ATT&CK group associated with the rule for mapping and correlation",
    )

    report: Annotated[set[str], BeforeValidator(lambda x: [x] if isinstance(x, str) else x)] | None = Field(
        default=None,
        description="List of reports or references associated with the rule for further reading and context",
    )

    reference: Annotated[set[str], BeforeValidator(lambda x: [x] if isinstance(x, str) else x)] | None = Field(
        default=None,
        description="List of external references or sources associated with the rule for validation and credibility",
    )

    hash: (
        Annotated[
            set[Annotated[str, StringConstraints(pattern=GENERIC_HASH_REGEX)]],
            BeforeValidator(
                lambda x: (
                    [x.lower()]
                    if isinstance(x, str) and GENERIC_HASH_REGEX.match(x.lower())
                    else [i.lower() for i in x if GENERIC_HASH_REGEX.match(i.lower())]
                )
            ),
        ]
        | None
    ) = Field(
        default=None,
        description="List of hashes associated with the rule for identification and correlation",
    )

    license: str | None = Field(
        default=None,
        description="License under which the rule is distributed for legal and usage considerations",
    )

    copyright: str | None = Field(
        default=None,
        description="Copyright information for the rule for attribution and legal purposes",
    )

    # Specific to Assemblyline
    al_score: int | None = Field(
        default=None,
        description="What to score the rule when running in Assemblyline",
    )

    # Ensure all the original_* fields are preserved after validation
    @model_validator(mode="after")
    def after_validation(cls, context):
        # Ensure we keep any extra fields that were added that start with "original_"
        for key, value in list(cls.model_extra.items()):
            if key.startswith("original_"):
                # Check if we're using the original field value in the resulting metadata
                original_key = key[9:]
                if (
                    isinstance(value, int)
                    and value == getattr(cls, original_key, None)
                    or f"{value}.0" == str(getattr(cls, original_key, None))
                ):
                    # If so, skip re-adding it
                    cls.model_extra.pop(key)
                    continue

                if list(value or "") == list(getattr(cls, original_key, None) or ""):
                    # If so, skip re-adding it
                    cls.model_extra.pop(key)
                    continue

                # Check to see if the value is a default that was auto-assigned
                if original_key in context.context.get("default_metadata", {}):
                    cls.model_extra.pop(key)
                    continue

                setattr(cls, key, value)
        return cls
