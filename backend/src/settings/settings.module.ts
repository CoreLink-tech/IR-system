import { Module } from '@nestjs/common';
import { SettingsController } from './settings.controller';
import { SettingsService } from './settings.service';
import { IpsModule } from '../ips/ips.module';

@Module({ imports: [IpsModule], controllers: [SettingsController], providers: [SettingsService] })
export class SettingsModule {}
