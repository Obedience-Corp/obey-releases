# Dot-source in the owning CI step. Never let a later native command mask failure.
function Invoke-CheckedPython {
    & python @args
    if ($LASTEXITCODE -ne 0) {
        throw ('Native Python command failed with exit code ' + $LASTEXITCODE)
    }
}
