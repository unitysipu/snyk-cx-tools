# converts API types into a snyk product
def convertTypeToProduct(inputType: str) -> str:
    containerTypes = ["deb", "linux", "dockerfile", "rpm", "apk"]
    iacTypes = [
        "k8sconfig",
        "helmconfig",
        "terraformconfig",
        "armconfig",
        "cloudformationconfig",
    ]
    codeTypes = ["sast"]

    if inputType in containerTypes:
        return "container"
    if inputType in iacTypes:
        return "iac"
    if inputType in codeTypes:
        return "sast"
    print(f"Unknown type: {inputType}, assuming opensource.")
    return "opensource"
