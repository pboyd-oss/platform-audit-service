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
        disableConcurrentBuilds()
        buildDiscarder(logRotator(numToKeepStr: '20'))
    }

    triggers {
        pollSCM('H/5 * * * *')
    }

    stages {
        stage('Build')      { steps { script { platformBuild() } } }
        stage('Archive')    { steps { script { platformArchive() } } }
        stage('Sign')       { steps { script { platformSign() } } }
        stage('Provenance') { steps { script { platformBuildProvenance() } } }
        stage('Deploy') {
            steps {
                container('deploy-sec-base') {
                    sh '''
                        skaffold render --build-artifacts=artifacts.json --profile=dev --output=rendered.yaml
                        kubectl apply --validate=false -f rendered.yaml
                    '''
                }
            }
        }
    }
}
