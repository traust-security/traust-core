from traust_core.v1.repositories.sql import apply_schema


def test_schema_statements_do_not_treat_literals_as_parameter_placeholders(engine):
    apply_schema(engine, ["SELECT ':as_of 10%' -- literal contract SQL, no bound parameters"])
