#!/usr/bin/env bash
cd "${0%/*}"
test -z "${WORKSPACE}" && export WORKSPACE=$(readlink -f .)
export PYTHONPATH=${PYTHONPATH}:${WORKSPACE}
echo "WORKSPACE is ${WORKSPACE}"
LOGLEVEL=${LOGLEVEL:-"debug"}
LOGFMT='%(asctime)-9s [%(funcName)-5s] %(levelname)s: %(message)s'
TEST_LOG="./pytest.log"
./dependency_test.py || exit 1
CMD=$(command -v python3)

# support for coverage
command -v coverage && echo "Coverage found" && CMD="coverage run --source=bfd" || echo "Coverage not found"

CMD="${CMD} -m pytest -W ignore -vv -s --verbose \
--show-capture all \
--log-format='${LOGFMT}' \
--log-cli-level=${LOGLEVEL} \
--log-file=${TEST_LOG} \
--log-file-level=${LOGLEVEL} \
--log-file-format='${LOGFMT}'"

# support for exit after first failure
test -n "${DROP}" && echo "Pytest will exit after first failure" && CMD="${CMD} -x "

# support for explicit test run
test -n "${TESTNAME}" && echo "Found testname ${TESTNAME}" && CMD="${CMD} -k ${TESTNAME}"

test -n "${TESTFILE}" && echo "Found testfile ./tests/${TESTFILE%%.py}.py" && CMD="${CMD} ./tests/${TESTFILE%%.py}.py"

echo ${CMD}

if [ -z "${JENKINS_URL}" ]
then
    echo "Manual run"
    eval "${CMD}"
    command -v coverage && coverage report -m
else
    echo "Jenkins run"
    eval "${CMD}"
fi
