pipeline {
    agent any
    
    environment {
        DOCKER_HUB_CREDENTIALS = credentials('docker-hub-credentials')
        APP_URL = "http://host.docker.internal:8888"
        WSO2_CLIENT_ID = "Iw1nIrWWSBHthS0P1WuXwkjfssUa"
        WSO2_TOKEN_URL = "https://host.docker.internal:9443/oauth2/token"
    }
    
    stages {
        stage('Récupérer le code') {
            steps {
                echo 'Récupération du code depuis GitHub...'
                checkout scm
            }
        }
        
        stage('SonarQube - Analyse') {
            steps {
                script {
                    try {
                        withSonarQubeEnv('sonarqube') {
                            sh '''
                                docker run --rm \
                                --network host \
                                -e SONAR_HOST_URL=http://localhost:9000 \
                                -v $(pwd):/usr/src \
                                sonarsource/sonar-scanner-cli \
                                -Dsonar.projectKey=mon-api-vuln \
                                -Dsonar.sources=/usr/src \
                                -Dsonar.inclusions=sqli/**/*.py,config/**/*.py \
                                -Dsonar.language=py \
                                -Dsonar.python.version=3
                            '''
                        }
                    } catch (Exception e) {
                        echo "⚠️ SonarQube a échoué, mais on continue le pipeline..."
                    }
                }
            }
        }
        
        stage('Builder Docker') {
            steps {
                echo 'Construction de l image Docker...'
                sh 'docker build -t umissa/mon-api-vuln .'
            }
        }
        
        stage('Scanner avec Trivy') {
            steps {
                echo 'Scan de sécurité avec Trivy (Analyse de l image)...'
                sh '''
                    docker run --rm \
                    -v /var/run/docker.sock:/var/run/docker.sock \
                    aquasec/trivy image \
                    --severity CRITICAL \
                    umissa/mon-api-vuln || true
                '''
            }
        }
        
        stage('Login & Push Docker Hub') {
            steps {
                sh 'echo $DOCKER_HUB_CREDENTIALS_PSW | docker login -u $DOCKER_HUB_CREDENTIALS_USR --password-stdin'
                sh 'docker push umissa/mon-api-vuln'
            }
        }

        stage('WSO2 - Validation OAuth2/OIDC') {
            steps {
                echo 'Validation OAuth2 via WSO2 Identity Server...'
                withCredentials([string(credentialsId: 'wso2-client-secret', variable: 'WSO2_SECRET')]) {
                    script {
                        def response = sh(
                            script: '''
                                curl -k -s -X POST https://host.docker.internal:9443/oauth2/token \
                                -H "Content-Type: application/x-www-form-urlencoded" \
                                -d "grant_type=client_credentials&client_id=${WSO2_CLIENT_ID}&client_secret=${WSO2_SECRET}"
                            ''',
                            returnStdout: true
                        ).trim()
                        echo "Réponse WSO2 : ${response}"
                        if (!response.contains("access_token")) {
                            error "❌ Échec authentification WSO2 - Déploiement bloqué !"
                        }
                        echo "✅ Token OAuth2 obtenu - Déploiement autorisé !"
                    }
                }
            }
        }
        
        stage('Déployer sur Kubernetes') {
            steps {
                echo 'Tentative de déploiement sur Kubernetes...'
                script {
                    sh 'kubectl --insecure-skip-tls-verify apply -f webapp.yaml || true'
                }
                echo 'Attente de démarrage des ressources...'
                sleep 20
            }
        }

        stage('OWASP ZAP DAST Scan') {
            steps {
                echo "Lancement du scan dynamique (DAST) léger sur ${APP_URL}..."
                script {
                    sh 'rm -rf zap-reports && mkdir -p zap-reports && chmod 777 zap-reports'
                    sh """
    docker run --rm \
    -u root \
    --memory=1g \
    --add-host=host.docker.internal:host-gateway \
    -v \$(pwd)/zap-reports:/zap/wrk/:rw \
    zaproxy/zap-stable zap-baseline.py \
    -t ${APP_URL} \
    -r zap_report.html || true
"""
                }
            }
        }

       stage('RGPD - Rapport de conformité') {
    steps {
        echo 'Génération du rapport de conformité RGPD...'
        script {
            sh '''
                cp rgpd_report.py zap-reports/rgpd_report.py
                docker run --rm \
                -v $(pwd)/zap-reports:/zap/wrk/ \
                python:3.9-alpine \
                python /zap/wrk/rgpd_report.py
            '''
        }
        echo '✅ Rapport RGPD généré !'
    }
}

    post {
        always {
            echo 'Archivage des rapports...'
            publishHTML([
                allowMissing: true,
                alwaysLinkToLastBuild: true,
                keepAll: true,
                reportDir: 'zap-reports',
                reportFiles: 'zap_report.html',
                reportName: 'OWASP ZAP Report'
            ])
            publishHTML([
                allowMissing: true,
                alwaysLinkToLastBuild: true,
                keepAll: true,
                reportDir: 'zap-reports',
                reportFiles: 'rgpd_report.html',
                reportName: 'Rapport RGPD'
            ])
        }
        failure {
            echo '❌ Pipeline terminé avec des erreurs.'
        }
        success {
            echo '✅ Pipeline terminé avec succès !'
        }
    }
}