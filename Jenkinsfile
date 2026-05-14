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
                container('kaniko') {
                    sh '''
                        cp /mitm-data/deps.ndjson ${WORKSPACE}/deps.ndjson 2>/dev/null \
                            || printf '[]' > ${WORKSPACE}/deps.ndjson
                    '''
                }
                script {
                    env.IMAGE_DIGEST = readFile("${WORKSPACE}/image.digest").trim()
                    writeJSON file: 'artifacts.json', json: [
                        builds: [[imageName: env.IMAGE, tag: "${env.IMAGE}@${env.IMAGE_DIGEST}", number: env.BUILD_NUMBER]]
                    ]
                    archiveArtifacts artifacts: 'artifacts.json,deps.ndjson', fingerprint: true
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
                script {
                    platformBuildProvenance()
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
