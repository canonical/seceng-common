import pydantic


class RsyncRelationUnitData(pydantic.BaseModel):
    path: str
    module: str
    read_only: bool = True
    comment: str
