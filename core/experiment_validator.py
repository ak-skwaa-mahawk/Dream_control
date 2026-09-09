class ParameterValidationError(Exception):
    pass

def validate_experiment(payload: dict) -> HarnessSpec:
    exp = payload.get("experiment", {})
    hid = exp.get("harness_id")
    
    if hid not in HARNESS_REGISTRY:
        raise ParameterValidationError(f"Illegal or unknown harness_id: {hid}")
        
    spec = HARNESS_REGISTRY[hid]
    params = exp.get("parameters", {})
    
    for key, expected_type in spec.param_schema.items():
        if key not in params:
            raise ParameterValidationError(f"Missing parameter: {key}")
        val = params[key]
        if not isinstance(val, expected_type):
            raise ParameterValidationError(f"Type mismatch for {key}: expected {expected_type}")
        
        min_v, max_v = spec.param_bounds[key]
        if not (min_v <= val <= max_v):
            raise ParameterValidationError(f"Value out of bounds for {key}: {val} not in [{min_v}, {max_v}]")
            
    return spec
