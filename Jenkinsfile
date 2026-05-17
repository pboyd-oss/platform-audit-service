@Library('jenkins-library') _

pipeline {
    agent {
        kubernetes {
            cloud env.TUXGRID_BUILD_CLOUD
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
        stage('Source Scan') {
            steps {
                build job: 'platform/services/audit-service/source-scan', wait: true
            }
        }
        stage('Build')      { steps { script { platformBuild() } } }
        stage('Archive')    { steps { script { platformArchive() } } }
        stage('Sign')       { steps { script { platformSign() } } }
        stage('Provenance') { steps { script { platformBuildProvenance() } } }
        stage('Promote')    { steps { script { platformPromote() } } }
    }
}
