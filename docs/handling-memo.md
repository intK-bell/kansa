## backend eploy
### deploy
cd /Users/aokikensaku/Documents/Devapps/kansa
SAM_CONFIG_ENV=dev ./scripts/deploy_backend.sh


### 確認
aws cloudformation describe-stacks --stack-name kansa-backend-dev --region ap-northeast-1 --query 'Stacks[0].StackStatus