#!/usr/bin/env bash
cd "${0%/*}"
LOGLEVEL=${LOGLEVEL:-"debug"}
LOGFMT='%(asctime)-9s [%(funcName)-5s] %(levelname)s: %(message)s'
TEST_LOG="./pytest.log"
./dependency_test.py || exit 1

CMD="python3 -m pytest -W ignore -vv -s --verbose --cov=bfd --cov-report term-missing \
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

echo "${CMD}"
eval "${CMD}"
