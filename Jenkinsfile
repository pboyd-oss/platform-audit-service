pipeline {
    agent {
        kubernetes {
            cloud 'kubernetes'
            inheritFrom 'platform-builder'
        }
    }

    environment {
        IMAGE = 'harbor.tuxgrid.com/platform/audit-service'
    }

    options {
        timeout(time: 30, unit: 'MINUTES')
        buildDiscarder(logRotator(numToKeepStr: '20'))
    }

    triggers {
        pollSCM('H/5 * * * *')
    }

    stages {
        stage('Build') {
            steps {
                container('kaniko') {
                    withCredentials([usernamePassword(
                            credentialsId: 'harbor-robot-platform',
                            usernameVariable: 'HARBOR_USER',
                            passwordVariable: 'HARBOR_PASS')]) {
                        sh '''
                            mkdir -p /kaniko/.docker
                            AUTH=$(printf '%s:%s' "${HARBOR_USER}" "${HARBOR_PASS}" | base64 | tr -d '\n')
                            printf '{"auths":{"harbor.tuxgrid.com":{"auth":"%s"}}}' "${AUTH}" \
                                > /kaniko/.docker/config.json
                            PLATFORM_CA_B64=$(base64 -w0 /mitm-data/ca.pem 2>/dev/null || true)
                            /kaniko/executor \
                                --context=dir://. \
                                --dockerfile=Dockerfile \
                                --build-arg "PLATFORM_CA_B64=${PLATFORM_CA_B64}" \
                                --build-arg HTTPS_PROXY=http://127.0.0.1:8080 \
                                --build-arg HTTP_PROXY=http://127.0.0.1:8080 \
                                --destination=${IMAGE}:${BUILD_NUMBER} \
                                --destination=${IMAGE}:latest \
                                --digest-file=${WORKSPACE}/image.digest
                        '''
                    }
                }
            }
        }

        stage('Archive') {
            steps {
                script {
                    env.IMAGE_DIGEST = readFile("${WORKSPACE}/image.digest").trim()
                    writeJSON file: 'artifacts.json', json: [
                        builds: [[imageName: env.IMAGE, tag: "${env.IMAGE}@${env.IMAGE_DIGEST}", number: env.BUILD_NUMBER]]
                    ]
                    archiveArtifacts artifacts: 'artifacts.json', fingerprint: true
                }
            }
        }

        stage('Sign') {
            steps {
                container('deploy-sec-base') {
                    withCredentials([
                        string(credentialsId: 'cosign-key', variable: 'COSIGN_PRIVATE_KEY'),
                        usernamePassword(
                            credentialsId: 'harbor-robot-platform',
                            usernameVariable: 'HARBOR_USER',
                            passwordVariable: 'HARBOR_PASS'),
                    ]) {
                        sh '''
                            printf '%s' "${COSIGN_PRIVATE_KEY}" > /tmp/cosign.key
                            chmod 600 /tmp/cosign.key
                            AUTH=$(printf '%s:%s' "${HARBOR_USER}" "${HARBOR_PASS}" | base64 | tr -d '\n')
                            mkdir -p ~/.docker
                            printf '{"auths":{"harbor.tuxgrid.com":{"auth":"%s"}}}' "${AUTH}" \
                                > ~/.docker/config.json
                            COSIGN_PASSWORD="" cosign sign --key /tmp/cosign.key --yes \
                                "${IMAGE}@${IMAGE_DIGEST}"
                            rm -f /tmp/cosign.key ~/.docker/config.json
                        '''
                    }
                }
            }
        }

        stage('Provenance') {
            steps {
                container('deploy-sec-base') {
                    withCredentials([
                        string(credentialsId: 'cosign-key', variable: 'COSIGN_PRIVATE_KEY'),
                        usernamePassword(
                            credentialsId: 'harbor-robot-platform',
                            usernameVariable: 'HARBOR_USER',
                            passwordVariable: 'HARBOR_PASS'),
                    ]) {
                        sh '''
                            printf '%s' "${COSIGN_PRIVATE_KEY}" > /tmp/cosign.key
                            chmod 600 /tmp/cosign.key
                            AUTH=$(printf '%s:%s' "${HARBOR_USER}" "${HARBOR_PASS}" | base64 | tr -d '\n')
                            mkdir -p ~/.docker
                            printf '{"auths":{"harbor.tuxgrid.com":{"auth":"%s"}}}' "${AUTH}" \
                                > ~/.docker/config.json

                            python3 - << 'PYEOF'
import json, os, datetime

deps = []
if os.path.exists("/mitm-data/deps.ndjson"):
    with open("/mitm-data/deps.ndjson") as f:
        for line in f:
            try:
                e = json.loads(line.strip())
                if e.get("status", 0) < 400 and e.get("url"):
                    dep = {"uri": e["url"]}
                    if e.get("sha256"):
                        dep["digest"] = {"sha256": e["sha256"]}
                    deps.append(dep)
            except Exception:
                pass

now = datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
provenance = {
    "predicateType": "https://slsa.dev/provenance/v1",
    "predicate": {
        "buildDefinition": {
            "buildType": "https://tuxgrid.com/buildType/jenkins-kaniko/v1",
            "externalParameters": {
                "ref": os.environ.get("GIT_COMMIT", ""),
                "repository": os.environ.get("GIT_URL", ""),
                "dockerfile": "Dockerfile",
            },
            "resolvedDependencies": deps,
        },
        "runDetails": {
            "builder": {"id": "https://jenkins.tuxgrid.com/job/" + os.environ.get("JOB_NAME", "") + "/" + os.environ.get("BUILD_NUMBER", "")},
            "metadata": {
                "invocationId": os.environ.get("BUILD_URL", ""),
                "startedOn": now,
                "finishedOn": now,
            },
        },
    },
}
with open("/tmp/provenance.json", "w") as f:
    json.dump(provenance, f, indent=2)
print("provenance.json: {} resolved dependencies".format(len(deps)))
PYEOF

                            COSIGN_PASSWORD="" cosign attest --key /tmp/cosign.key --yes \
                                --type slsaprovenance1 \
                                --predicate /tmp/provenance.json \
                                "${IMAGE}@${IMAGE_DIGEST}"

                            syft "${IMAGE}@${IMAGE_DIGEST}" \
                                --output cyclonedx-json=/tmp/sbom.json

                            COSIGN_PASSWORD="" cosign attest --key /tmp/cosign.key --yes \
                                --type cyclonedx \
                                --predicate /tmp/sbom.json \
                                "${IMAGE}@${IMAGE_DIGEST}"

                            rm -f /tmp/cosign.key ~/.docker/config.json /tmp/provenance.json /tmp/sbom.json
                        '''
                    }
                }
            }
        }

        stage('Deploy') {
            steps {
                container('deploy-sec-base') {
                    sh '''
                        skaffold render --build-artifacts=artifacts.json --output=rendered.yaml
                        skaffold apply rendered.yaml
                    '''
                }
            }
        }
    }
}
