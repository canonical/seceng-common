import pydantic


class RsyncRelationUnitData(pydantic.BaseModel):
    path: str
    module: str
    read_only: bool = True
    disable_listing: bool = False
    comment: str
