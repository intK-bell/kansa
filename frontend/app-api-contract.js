export const APP_API_METHODS = Object.freeze([
  'getCurrentUser',
  'saveDisplayName',
  'listRooms',
  'switchRoom',
  'createRoom',
  'getTeam',
  'listTeamMembers',
  'updateTeamMember',
  'leaveTeam',
  'deleteTeam',
  'deleteAccount',
  'listFolders',
  'createFolder',
  'deleteFolder',
  'setFolderPassword',
  'listFolderMembers',
  'removeFolderMember',
  'listPhotos',
  'searchPhotos',
  'uploadPhoto',
  'updatePhoto',
  'deletePhoto',
  'listPhotoComments',
  'createPhotoComment',
  'updatePhotoComment',
  'deletePhotoComment',
  'listQuests',
  'createQuest',
  'updateQuest',
  'deleteQuest',
  'createQuestComment',
  'deleteQuestComment',
  'createInvite',
  'acceptInvite',
  'revokeInvite',
  'getSubscription',
  'startSubscriptionCheckout',
  'changeSubscription',
  'exportFolder',
]);

export const ACCOUNT_ROOM_API_METHODS = Object.freeze([
  'getCurrentUser', 'saveDisplayName', 'listRooms', 'switchRoom', 'createRoom',
]);

export const FOLDER_API_METHODS = Object.freeze([
  'listFolders', 'createFolder', 'deleteFolder', 'setFolderPassword',
  'listFolderMembers', 'removeFolderMember',
]);

export const PHOTO_API_METHODS = Object.freeze([
  'listPhotos', 'uploadPhoto', 'updatePhoto', 'deletePhoto', 'listPhotoComments',
  'createPhotoComment', 'updatePhotoComment', 'deletePhotoComment',
]);

export const QUEST_API_METHODS = Object.freeze([
  'listQuests', 'createQuest', 'updateQuest', 'deleteQuest',
  'createQuestComment', 'deleteQuestComment',
]);

export const SEARCH_EXPORT_API_METHODS = Object.freeze(['searchPhotos', 'exportFolder']);

export const TEAM_INVITE_BILLING_API_METHODS = Object.freeze([
  'getTeam', 'listTeamMembers', 'updateTeamMember', 'leaveTeam', 'deleteTeam', 'deleteAccount',
  'createInvite', 'acceptInvite', 'revokeInvite', 'getSubscription',
  'startSubscriptionCheckout', 'changeSubscription',
]);

export function assertApiMethods(candidate, methods, label = 'App API adapter') {
  if (!candidate || typeof candidate !== 'object') throw new TypeError(`${label} must be an object.`);
  const missing = methods.filter((method) => typeof candidate[method] !== 'function');
  if (missing.length) throw new TypeError(`${label} is missing methods: ${missing.join(', ')}`);
  return candidate;
}

export function assertAppApi(candidate) {
  return assertApiMethods(candidate, APP_API_METHODS);
}
