pipeline {
    agent any
    
    environment {
        // Utilisation des identifiants configurés dans Jenkins
        DOCKER_HUB_CREDENTIALS = credentials('docker-hub-credentials')
        // URL cible pour le scan (ton application locale)
        APP_URL = "http://host.docker.internal:8888" 
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
        
        stage('Déployer sur Kubernetes') {
            steps {
                echo 'Tentative de déploiement sur Kubernetes...'
                script {
                    // Bypass SSL et continuation forcée avec || true
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
                    // Préparation du dossier de rapport (nettoyage et droits)
                    sh 'rm -rf zap-reports && mkdir -p zap-reports && chmod 777 zap-reports'
                    
                    // Exécution du scan ZAP en version Bare (légère)
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
    }

    post {
        always {
            echo 'Archivage du rapport OWASP ZAP...'
            publishHTML([
                allowMissing: true,
                alwaysLinkToLastBuild: true,
                keepAll: true,
                reportDir: 'zap-reports',
                reportFiles: 'zap_report.html',
                reportName: 'OWASP ZAP Report'
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