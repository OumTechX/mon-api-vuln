pipeline {
    agent any
    
    environment {
        DOCKER_HUB_CREDENTIALS = credentials('docker-hub-credentials')
        // On utilise host.docker.internal pour que le container ZAP puisse atteindre ton localhost:8888
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
                        echo "SonarQube a échoué mais on continue le pipeline..."
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
        echo 'Scan de sécurité avec Trivy (Mode audit)...'
        sh '''
            docker run --rm \
            -v /var/run/docker.sock:/var/run/docker.sock \
            aquasec/trivy image \
            --severity CRITICAL \
            umissa/mon-api-vuln || true
        ''' 
        // Le "|| true" permet de continuer même si des failles sont trouvées
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
                echo 'Déploiement sur Kubernetes...'
                sh 'kubectl apply -f webapp.yaml'
                echo 'Attente de 30 secondes pour le démarrage des pods...'
                sleep 30
            }
        }

        stage('OWASP ZAP DAST Scan') {
            steps {
                echo "Lancement du scan dynamique sur ${APP_URL}..."
                script {
                    // Création du dossier pour le rapport
                    sh 'mkdir -p zap-reports && chmod 777 zap-reports'
                    
                    // --add-host permet au container de trouver ton localhost via l'URL configurée
                    sh """
    docker run --rm \
    --add-host=host.docker.internal:host-gateway \
    -v \$(pwd)/zap-reports:/zap/wrk/:rw \
    owasp/zap2docker-stable zap-baseline.py \
    -t ${APP_URL} \
    -r zap_report.html || true
                     """
                }
            }
        }
    }

    post {
        always {
            // Publie le rapport ZAP dans l'interface Jenkins
            publishHTML([
                allowMissing: false,
                alwaysLinkToLastBuild: true,
                keepAll: true,
                reportDir: 'zap-reports',
                reportFiles: 'zap_report.html',
                reportName: 'OWASP ZAP Report'
            ])
        }
        failure {
            echo '❌ Pipeline échoué !'
        }
        success {
            echo '✅ Pipeline réussi !'
        }
    }
}